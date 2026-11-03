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
        private readonly UsbWriteControl? _accessControl;

        /// <summary>Параметр конструктора: модуль перекрытия доступа к томам (для незарегистрированных носителей).</summary>
        public UsbWriteControl? VolumeAccessControl => _accessControl;

        // Одновременная обработка одного подключения; новые события во время скана — в очередь.
        private readonly SemaphoreSlim _processGate = new(1, 1);
        private CancellationTokenSource? _runCts;
        private bool _started;
        private RemovableDeviceEventArgs? _lastArrival; // для ручного повторного скана из UI

        // ---- постоянный мониторинг зарегистрированных носителей (фоновый опрос) ----
        private CancellationTokenSource? _watchCts;
        private Task? _watchTask;
        private readonly Dictionary<string, HashSet<string>> _knownFiles = new(StringComparer.OrdinalIgnoreCase);
        private readonly DlpPolicyConfig Policy => _policy;

        /// <summary>Новый файл с конфиденциальной информацией на зарегистрированной флешке.</summary>
        public event Action<RemovableVolumeInfo, string, IReadOnlyList<ContentFinding>>? SensitiveFileAppeared;

        public event EventHandler<ScanSessionSummary>? SessionUpdated;
        public event EventHandler<string>? ActivityLogged;

        public IReadOnlyDictionary<string, ScanSessionSummary> ActiveSessions { get; private set; } =
            new Dictionary<string, ScanSessionSummary>();

        public UsbDlpAgent(
            IRemovableDeviceWatcher watcher,
            IContentScanner scanner,
            IEnforcementModule enforcement,
            IIncidentLogger logger,
            DlpPolicyConfig policy,
            UsbWriteControl? accessControl = null)
        {
            _watcher = watcher;
            _scanner = scanner;
            _enforcement = enforcement;
            _logger = logger;
            _policy = policy;
            _accessControl = accessControl;

            _watcher.DeviceArrived += OnDeviceArrived;
            _watcher.DeviceRemoved += OnDeviceRemoved;
        }

        public void Start()
        {
            if (_started) return;
            _started = true;
            _runCts = new CancellationTokenSource();
            _watcher.Start();
            StartVolumeWatch(_runCts.Token);
            ActivityLogged?.Invoke(this, "Агент запущен: мониторинг съёмных носителей активен.");
        }

        public async Task StopAsync()
        {
            if (!_started) return;
            _started = false;
            _runCts?.Cancel();
            _watchCts?.Cancel();
            if (_watchTask is not null)
            {
                try { await _watchTask.ConfigureAwait(false); }
                catch (OperationCanceledException) { }
            }
            await _watcher.StopAsync();
            ActivityLogged?.Invoke(this, "Агент остановлен.");
        }

        // ================= ПОСТОЯННЫЙ МОНИТОРИНГ НОСИТЕЛЕЙ =================

        /// <summary>Фоновый опрос зарегистрированных томов: новые файлы → проверка на конфиденциальность.</summary>
        private void StartVolumeWatch(CancellationToken ct)
        {
            _watchCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            var token = _watchCts.Token;
            _watchTask = Task.Run(async () =>
            {
                while (!token.IsCancellationRequested)
                {
                    try
                    {
                        foreach (var s in ActiveSessions.Values.Where(s =>
                                     _policy.IsWhitelisted(s.Volume.DeviceId, s.Volume.SerialNumber)))
                            await CheckNewFilesAsync(s.Volume, token).ConfigureAwait(false);

                        foreach (var v in await _watcher.GetRemovableVolumesAsync(token).ConfigureAwait(false))
                            if (_policy.IsWhitelisted(v.DeviceId, v.SerialNumber))
                                await CheckNewFilesAsync(v, token).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException) { break; }
                    catch (Exception) { /* том мог быть извлечён между проверками */ }

                    try { await Task.Delay(TimeSpan.FromSeconds(5), token).ConfigureAwait(false); }
                    catch (OperationCanceledException) { break; }
                }
            }, token);
        }

        private async Task CheckNewFilesAsync(RemovableVolumeInfo volume, CancellationToken ct)
        {
            string root = volume.DriveLetter.EndsWith(':') ? volume.DriveLetter + "\\" : volume.DriveLetter;
            if (!Directory.Exists(root)) return;

            HashSet<string> known;
            lock (_knownFiles)
            {
                if (!_knownFiles.TryGetValue(volume.DriveLetter, out known!))
                    _knownFiles[volume.DriveLetter] = known = [];
            }

            List<string> newFiles = [];
            try
            {
                foreach (var f in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
                    lock (known)
                        if (known.Add(f)) newFiles.Add(f);
            }
            catch (IOException) { return; }
            catch (UnauthorizedAccessException) { return; }

            if (newFiles.Count == 0) return;

            foreach (var f in newFiles)
            {
                ct.ThrowIfCancellationRequested();
                FileScanResult res;
                try
                {
                    res = await _scanner.ScanFileAsync(f, Path.GetRelativePath(root, f), ct).ConfigureAwait(false);
                }
                catch (IOException) { continue; }

                if (!res.IsCommitted) continue;

                string full = f;
                NotifyClean($"Внимание! На зарегистрированной флешке {volume.DriveLetter} обнаружен новый файл " +
                            $"с конфиденциальной информацией:\n• {full}\n" +
                            $"Находки: {string.Join(", ", res.Findings.Select(x => x.RuleName).Distinct())}");
                SensitiveFileAppeared?.Invoke(volume, full, res.Findings);

                await LogSimpleAsync("SensitiveFileCopied", IncidentSeverity.High,
                    $"Перенос конфиденциальных данных: файл {full} записан на зарегистрированный носитель " +
                    $"{volume.DriveLetter} (SN={volume.SerialNumber}).",
                    volume, EnforcementAction.None).ConfigureAwait(false);
            }
        }

        private void RememberSnapshot(RemovableVolumeInfo volume)
        {
            string root = volume.DriveLetter.EndsWith(':') ? volume.DriveLetter + "\\" : volume.DriveLetter;
            var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                if (Directory.Exists(root))
                    foreach (var f in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
                        set.Add(f);
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
            lock (_knownFiles) _knownFiles[volume.DriveLetter] = set;
        }

        private void NotifyClean(string message) =>
            ActivityLogged?.Invoke(this, $"[{DateTime.Now:HH:mm:ss}] {message}");

        private void OnDeviceArrived(object? sender, RemovableDeviceEventArgs e)
        {
            _lastArrival = e;
            foreach (var vol in e.Volumes)
                _ = HandleArrivalAsync(vol, e.Device);
        }

        /// <summary>Ручной запуск проверки выбранного устройства из интерфейса.</summary>
        public Task RescanLastDeviceAsync()
        {
            var e = _lastArrival ?? throw new InvalidOperationException("Устройства ещё не подключались.");
            return e.Volumes.Count > 0 ? HandleArrivalAsync(e.Volumes[0], e.Device) : Task.CompletedTask;
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
                // 1. Зарегистрированный носитель (белый список): полный доступ + скан содержимого
                //    с выводом путей файлов, содержащих конфиденциальную информацию.
                bool registered = _policy.IsWhitelisted(volume.DeviceId, volume.SerialNumber);
                if (registered)
                {
                    await LogSimpleAsync("DeviceAllowed", IncidentSeverity.Info,
                        $"Флешка зарегистрирована ({volume.DeviceId}, SN={volume.SerialNumber}). Права доступа не ограничиваются.",
                        volume, EnforcementAction.None).ConfigureAwait(false);

                    summary.Stage = DeviceProcessingStage.Scanning;
                    var regPaths = new List<string>();
                    string rootR = volume.DriveLetter.EndsWith(':') ? volume.DriveLetter + "\\" : volume.DriveLetter;
                    await foreach (var res in _scanner.ScanVolumeAsync(volume, null, _runCts?.Token ?? CancellationToken.None)
                                       .ConfigureAwait(false))
                    {
                        foreach (var f in res.Findings)
                            summary.FindingsByCategory[f.Category] =
                                summary.FindingsByCategory.GetValueOrDefault(f.Category) + 1;
                        if (res.IsCommitted)
                        {
                            string full = Path.Combine(rootR, res.RelativePath);
                            regPaths.Add(full);
                            summary.FindingsTotal += res.Findings.Count;
                        }
                    }

                    // Запоминаем снимок файлов — по нему фоновый монитор ловит НОВЫЕ файлы.
                    RememberSnapshot(volume);

                    if (regPaths.Count > 0)
                    {
                        summary.ActionApplied = EnforcementAction.None;
                        Notify(summary, $"Внимание! В файлах зарегистрированной флешки найдена конфиденциальная информация:\n• " +
                                        string.Join("\n• ", regPaths));
                        var incReg = new SecurityIncident
                        {
                            EventType = "RegisteredSensitiveFiles",
                            Severity = IncidentSeverity.High,
                            VidPid = volume.DeviceId.ToString(),
                            SerialNumber = volume.SerialNumber,
                            ProductName = device.ProductName,
                            Manufacturer = device.Manufacturer,
                            DriveLetters = volume.DriveLetter,
                            Description = $"Зарегистрированный носитель {volume.DriveLetter}: в {regPaths.Count} файлах обнаружены " +
                                          $"паспортные данные/СНИЛС/ИНН/почта/телефон. Пути:\n{string.Join("; ", regPaths)}",
                            FindingsCount = summary.FindingsTotal,
                        };
                        await _logger.LogAsync(incReg).ConfigureAwait(false);
                        SensitiveFileAppeared?.Invoke(volume, string.Join("\n", regPaths), []);
                    }
                    else
                    {
                        Notify(summary, $"Зарегистрированная флешка {volume.DriveLetter}: конфиденциальных данных нет.");
                    }

                    summary.FinishedAtUtc = DateTime.UtcNow;
                    summary.Stage = DeviceProcessingStage.Completed;
                    return;
                }

                // 2. НЕзарегистрированная флешка: полное ограничение доступа (чтение + запись).
                summary.Stage = DeviceProcessingStage.Enforcing;
                string denyDetail = "";
                if (_enforcement is RegistryEnforcementModule rem0)
                {
                    bool ro0 = await rem0.SetReadOnlyAsync(volume.DeviceId, volume.SerialNumber, volume.DriveLetter)
                                         .ConfigureAwait(false);
                    denyDetail = rem0.LastReadOnlyDetail ?? "";
                    _ = ro0;
                }
                if (_accessControl is not null)
                {
                    bool denied = _accessControl.DenyVolumeAccess(volume.DriveLetter);
                    denyDetail += denied
                        ? " | Доступ к тому перекрыт (чтение и запись запрещены)."
                        : " | Перекрытие доступа не удалось (нужен запуск от администратора).";
                }
                Notify(summary, $"Незарегистрированный носитель {volume.DriveLetter}: доступ ограничен (копирование и чтение запрещены). {denyDetail}");
                await LogSimpleAsync("UnregisteredBlocked", IncidentSeverity.High,
                    $"Незарегистрированное устройство ({volume.DeviceId}, SN={volume.SerialNumber}) заблокировано: " +
                    $"чтение и копирование запрещены.{denyDetail}",
                    volume, EnforcementAction.SetReadOnly).ConfigureAwait(false);

                summary.FinishedAtUtc = DateTime.UtcNow;
                summary.Stage = DeviceProcessingStage.Completed;
                return;
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
            bool restored = _enforcement is RegistryEnforcementModule remR
                ? await remR.RestoreReadWriteAsync(volume.DeviceId, volume.SerialNumber, volume.DriveLetter).ConfigureAwait(false)
                : await _enforcement.RestoreReadWriteAsync(volume.DeviceId, volume.SerialNumber).ConfigureAwait(false);

            lock (_knownFiles) _knownFiles.Remove(volume.DriveLetter);

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
