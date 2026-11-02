using System.IO;
using DLP.UsbController.Enums;
using DLP.UsbController.Interfaces;
using DLP.UsbController.Models;

namespace DLP.UsbController.Services
{
    /// <summary>
    /// Ядро DLP-агента: связывает WMI-наблюдатель, сканер содержимого, модуль принуждения
    /// и NDJSON-журнал в конвейер «обнаружение → идентификация → сопоставление томов →
    /// статический анализ → применение политики → регистрация инцидента → отправка на центр».
    /// </summary>
    public sealed class UsbDlpAgent : IAsyncDisposable
    {
        private readonly IRemovableDeviceWatcher _watcher;
        private readonly IContentScanner _scanner;
        private readonly IEnforcementModule _enforcement;
        private readonly IIncidentLogger _logger;
        private readonly DlpPolicyConfig _policy;

        // Одновременная обработка одного подключения; новые события во время скана — в очередь.
        private readonly SemaphoreSlim _processGate = new(1, 1);
        private CancellationTokenSource? _runCts;
        private bool _started;

        public event EventHandler<ScanSessionSummary>? SessionUpdated;
        public event EventHandler<string>? ActivityLogged;

        public IReadOnlyDictionary<string, ScanSessionSummary> ActiveSessions { get; private set; } =
            new Dictionary<string, ScanSessionSummary>();

        public UsbDlpAgent(
            IRemovableDeviceWatcher watcher,
            IContentScanner scanner,
            IEnforcementModule enforcement,
            IIncidentLogger logger,
            DlpPolicyConfig policy)
        {
            _watcher = watcher;
            _scanner = scanner;
            _enforcement = enforcement;
            _logger = logger;
            _policy = policy;

            _watcher.DeviceArrived += OnDeviceArrived;
            _watcher.DeviceRemoved += OnDeviceRemoved;
        }

        public void Start()
        {
            if (_started) return;
            _started = true;
            _runCts = new CancellationTokenSource();
            _watcher.Start();
            ActivityLogged?.Invoke(this, "Агент запущен: мониторинг съёмных носителей активен.");
        }

        public async Task StopAsync()
        {
            if (!_started) return;
            _started = false;
            _runCts?.Cancel();
            await _watcher.StopAsync();
            ActivityLogged?.Invoke(this, "Агент остановлен.");
        }

        private void OnDeviceArrived(object? sender, RemovableDeviceEventArgs e)
        {
            foreach (var vol in e.Volumes)
                _ = HandleArrivalAsync(vol, e.Device);
        }

        private void OnDeviceRemoved(object? sender, RemovableDeviceEventArgs e)
        {
            foreach (var vol in e.Volumes)
                _ = HandleRemovalAsync(vol);
        }

        private async Task HandleArrivalAsync(RemovableVolumeInfo volume, UsbDeviceInfo device)
        {
            await _processGate.WaitAsync().ConfigureAwait(false);
            var summary = new ScanSessionSummary
            {
                Volume = volume,
                StartedAtUtc = DateTime.UtcNow,
                Stage = DeviceProcessingStage.Detected,
            };
            SetSession(volume.DriveLetter, summary);
            Notify(summary, $"Обнаружено подключение: {volume}");

            try
            {
                // 1. Белый список корпоративных носителей — пропускаем без ограничений.
                if (_policy.IsWhitelisted(volume.DeviceId, volume.SerialNumber))
                {
                    await LogSimpleAsync("DeviceAllowed", IncidentSeverity.Info,
                        $"Устройство в белом списке ({volume.DeviceId}, SN={volume.SerialNumber}). Ограничения не применяются.",
                        volume, EnforcementAction.None).ConfigureAwait(false);
                    summary.Stage = DeviceProcessingStage.Completed;
                    return;
                }

                // 2. Немедленно ограничиваем запись, пока идёт анализ (защита от копирования «на лету»).
                summary.Stage = DeviceProcessingStage.Enforcing;
                if (_policy.DefaultAction is EnforcementAction.SetReadOnly or EnforcementAction.QuarantineFiles)
                {
                    bool ro = await _enforcement.SetReadOnlyAsync(volume.DeviceId, volume.SerialNumber)
                                                  .ConfigureAwait(false);
                    Notify(summary, ro
                        ? $"Том {volume.DriveLetter} переведён в режим «только чтение» (реестр WriteProtect=1)."
                        : $"Не удалось изменить реестр (нет прав?) — том {volume.DriveLetter} остаётся доступным для записи.");
                    await LogSimpleAsync("EnforcementReadOnly", ro ? IncidentSeverity.Medium : IncidentSeverity.High,
                        ro ? "Установлен режим только чтение." : "Попытка установки R/O не удалась (требуется elevated).",
                        volume, EnforcementAction.SetReadOnly).ConfigureAwait(false);
                }

                // 3. Статический анализ содержимого тома.
                summary.Stage = DeviceProcessingStage.Scanning;
                var compromised = new List<FileScanResult>();
                var findingsByFile = new Dictionary<string, IReadOnlyList<ContentFinding>>(StringComparer.OrdinalIgnoreCase);

                var progress = new Progress<ScanProgress>(p =>
                {
                    summary.FilesScanned = p.FilesScanned;
                    summary.FilesSkipped = p.FilesSkipped;
                    summary.FindingsTotal = p.FindingsSoFar;
                    Notify(summary, $"Скан {volume.DriveLetter}: файлов {p.FilesScanned}, находок {p.FindingsSoFar}");
                });

                string root = volume.DriveLetter.EndsWith(':') ? volume.DriveLetter + "\\" : volume.DriveLetter;
                await foreach (var res in _scanner.ScanVolumeAsync(volume, progress, _runCts?.Token ?? CancellationToken.None)
                                   .ConfigureAwait(false))
                {
                    foreach (var f in res.Findings)
                        summary.FindingsByCategory[f.Category] =
                            summary.FindingsByCategory.GetValueOrDefault(f.Category) + 1;

                    if (res.IsCommitted)
                    {
                        compromised.Add(res);
                        findingsByFile[Path.Combine(root, res.RelativePath)] = res.Findings;
                    }
                }

                // 4. Срабатывание политики → меры принуждения.
                if (compromised.Count > 0)
                {
                    summary.ActionApplied = _policy.DefaultAction;
                    IReadOnlyList<QuarantineRecord> quarantined = [];

                    if (_policy.DefaultAction == EnforcementAction.QuarantineFiles)
                    {
                        summary.Stage = DeviceProcessingStage.Enforcing;
                        quarantined = await _enforcement
                            .QuarantineFilesAsync(findingsByFile.Keys, findingsByFile, _runCts?.Token ?? CancellationToken.None)
                            .ConfigureAwait(false);
                        Notify(summary, $"Карантин: изъято файлов {quarantined.Count}, установлены заглушки.");
                    }

                    var incident = new SecurityIncident
                    {
                        EventType = "PolicyViolation",
                        Severity = compromised.SelectMany(c => c.Findings).Max(f => f.Severity),
                        VidPid = volume.DeviceId.ToString(),
                        SerialNumber = volume.SerialNumber,
                        ProductName = device.ProductName,
                        Manufacturer = device.Manufacturer,
                        DriveLetters = volume.DriveLetter,
                        Description = $"В файлах тома {volume.DriveLetter} обнаружена конфиденциальная информация " +
                                      $"({compromised.Sum(c => c.Findings.Count)} фрагментов в {compromised.Count} файлах).",
                        ActionApplied = _policy.DefaultAction,
                        FindingsCount = compromised.Sum(c => c.Findings.Count),
                        Findings = compromised.SelectMany(c => c.Findings).ToArray(),
                        QuarantinedFiles = quarantined,
                    };
                    await _logger.LogAsync(incident).ConfigureAwait(false);
                    summary.IncidentsLogged++;
                    Notify(summary, $"Инцидент {incident.Id[..8]} зарегистрирован и поставлен в очередь отправки.");
                }
                else
                {
                    await LogSimpleAsync("ScanClean", IncidentSeverity.Info,
                        $"Том {volume.DriveLetter}: конфиденциальной информации не обнаружено.",
                        volume, EnforcementAction.None).ConfigureAwait(false);
                }

                summary.FinishedAtUtc = DateTime.UtcNow;
                summary.Stage = DeviceProcessingStage.Completed;
            }
            catch (OperationCanceledException)
            {
                summary.Stage = DeviceProcessingStage.Failed;
                summary.LastError = "Обработка прервана остановкой агента.";
            }
            catch (Exception ex)
            {
                summary.Stage = DeviceProcessingStage.Failed;
                summary.LastError = ex.Message;
                await LogSimpleAsync("AgentError", IncidentSeverity.High, $"Сбой обработки: {ex.Message}",
                    volume, EnforcementAction.None).ConfigureAwait(false);
            }
            finally
            {
                Notify(summary, $"Завершение обработки тома {volume.DriveLetter}.");
                _processGate.Release();
            }
        }

        private async Task HandleRemovalAsync(RemovableVolumeInfo volume)
        {
            // Устройство извлечено — снимаем ограничение реестра, логируем событие.
            bool restored = await _enforcement
                .RestoreReadWriteAsync(volume.DeviceId, volume.SerialNumber)
                .ConfigureAwait(false);

            await LogSimpleAsync("DeviceRemoval", IncidentSeverity.Info,
                $"Том {volume.DriveLetter} отключён. Права записи восстановлены: {(restored ? "да" : "нет/не требовалось")}.",
                volume, restored ? EnforcementAction.RestoreReadWrite : EnforcementAction.None).ConfigureAwait(false);

            RemoveSession(volume.DriveLetter);
        }

        private async Task LogSimpleAsync(string eventType, IncidentSeverity sev, string description,
            RemovableVolumeInfo volume, EnforcementAction action)
        {
            var inc = new SecurityIncident
            {
                EventType = eventType,
                Severity = sev,
                VidPid = volume.DeviceId.ToString(),
                SerialNumber = volume.SerialNumber,
                DriveLetters = volume.DriveLetter,
                Description = description,
                ActionApplied = action,
            };
            await _logger.LogAsync(inc).ConfigureAwait(false);
        }

        private void SetSession(string letter, ScanSessionSummary s)
        {
            var dict = new Dictionary<string, ScanSessionSummary>(ActiveSessions as Dictionary<string, ScanSessionSummary>
                ?? []) { [letter] = s };
            ActiveSessions = dict;
        }

        private void RemoveSession(string letter)
        {
            var dict = new Dictionary<string, ScanSessionSummary>(ActiveSessions as Dictionary<string, ScanSessionSummary>
                ?? []);
            dict.Remove(letter);
            ActiveSessions = dict;
        }

        private void Notify(ScanSessionSummary s, string message)
        {
            SessionUpdated?.Invoke(this, s);
            ActivityLogged?.Invoke(this, $"[{DateTime.Now:HH:mm:ss}] {message}");
        }

        public async ValueTask DisposeAsync()
        {
            await StopAsync().ConfigureAwait(false);
            _watcher.DeviceArrived -= OnDeviceArrived;
            _watcher.DeviceRemoved -= OnDeviceRemoved;
            _processGate.Dispose();
            _runCts?.Dispose();
        }
    }
}
