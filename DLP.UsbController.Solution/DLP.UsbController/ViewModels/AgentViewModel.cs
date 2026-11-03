using System.ComponentModel;
using System.Runtime.CompilerServices;
using DLP.UsbController.Enums;
using DLP.UsbController.Interfaces;
using DLP.UsbController.Models;
using DLP.UsbController.Services;

namespace DLP.UsbController.ViewModels
{
    /// <summary>
    /// ViewModel окна DLP-агента: состояние агента для статус-бара/трея, журнал активности,
    /// список инцидентов, таблица устройств (паттерн State) и содержимое карантина.
    /// </summary>
    public sealed class AgentViewModel : INotifyPropertyChanged, IAsyncDisposable
    {
        private readonly UsbDlpAgent _agent;
        private readonly IIncidentLogger _logger;
        private readonly QuarantineStore? _quarantineStore;
        private readonly UsbWriteControl? _writeControl;
        private readonly RegistryEnforcementModule? _enforcement;

        public event PropertyChangedEventHandler? PropertyChanged;

        public BindingList<string> ActivityLog { get; } = [];
        public BindingList<SecurityIncident> Incidents { get; } = [];
        public BindingList<ScanSessionSummaryRow> Sessions { get; } = [];
        public BindingList<DeviceRow> Devices { get; } = [];
        public BindingList<QuarantineEntry> Quarantine { get; } = [];

        private bool _isRunning;
        public bool IsRunning
        {
            get => _isRunning;
            private set { _isRunning = value; OnPropertyChanged(); OnPropertyChanged(nameof(CanStart)); OnPropertyChanged(nameof(CanStop)); }
        }

        public bool CanStart => !IsRunning;
        public bool CanStop => IsRunning;

        private string _statusText = "Агент остановлен";
        public string StatusText
        {
            get => _statusText;
            private set { _statusText = value; OnPropertyChanged(); }
        }

        public int TotalFindings { get; private set; }
        public int QuarantinedFiles { get; private set; }
        public int DeliveredIncidents { get; private set; }
        public int BlockedDevices => Devices.Count(d => d.State is DeviceState.Blocked or DeviceState.Quarantined);
        public int ScanningDevices => Devices.Count(d => d.State == DeviceState.Scanning);
        public bool IsElevated => UsbWriteControl.IsElevated();

        public DlpPolicyConfig Policy { get; }
        public string QuarantineDirectory => _quarantineStore?.RootDirectory ?? Policy.QuarantineDirectory;

        public AgentViewModel(
            UsbDlpAgent agent,
            IIncidentLogger logger,
            DlpPolicyConfig policy,
            QuarantineStore? quarantineStore = null,
            UsbWriteControl? writeControl = null,
            RegistryEnforcementModule? enforcement = null)
        {
            _agent = agent;
            _logger = logger;
            _quarantineStore = quarantineStore;
            _writeControl = writeControl;
            _enforcement = enforcement;
            Policy = policy;

            _agent.ActivityLogged += (_, msg) => OnUi(() =>
            {
                ActivityLog.Insert(0, msg);
                while (ActivityLog.Count > 500) ActivityLog.RemoveAt(ActivityLog.Count - 1);
            });

            _agent.SessionUpdated += (_, s) => OnUi(() =>
            {
                var row = Sessions.FirstOrDefault(r => r.DriveLetter == s.Volume.DriveLetter);
                if (row is null) Sessions.Insert(0, ScanSessionSummaryRow.From(s));
                else row.Update(s);
                while (Sessions.Count > 50) Sessions.RemoveAt(Sessions.Count - 1);

                // Таблица устройств: состояние по паттерну State.
                var dev = Devices.FirstOrDefault(d => d.DriveLetter == s.Volume.DriveLetter);
                if (dev is null)
                {
                    dev = DeviceRow.From(s);
                    Devices.Insert(0, dev);
                }
                else dev.Update(s);
                while (Devices.Count > 50) Devices.RemoveAt(Devices.Count - 1);
                RefreshStats();
            });

            _logger.IncidentLogged += (_, inc) => OnUi(() =>
            {
                Incidents.Insert(0, inc);
                while (Incidents.Count > 300) Incidents.RemoveAt(Incidents.Count - 1);
                TotalFindings += inc.FindingsCount;
                QuarantinedFiles += inc.QuarantinedFiles.Count;
                if (inc.DeliveryStatus == IncidentDeliveryStatus.Delivered) DeliveredIncidents++;
                RefreshStats();
            });

            ReloadQuarantine();
        }

        /// <summary>Маршалинг событий из фоновых потоков в UI-поток задаёт форма.</summary>
        public Action<Action>? UiMarshal { get; set; }
        private void OnUi(Action a) => (UiMarshal ?? (act => act()))(a);

        public void Start()
        {
            _agent.Start();
            IsRunning = true;
            StatusText = $"Агент работает. Политика: {Policy.DefaultAction}, режим запуска: {(IsElevated ? "администратор" : "обычный пользователь")}";
        }

        public async Task StopAsync()
        {
            await _agent.StopAsync();
            IsRunning = false;
            StatusText = "Агент остановлен";
        }

        /// <summary>Ручная проверка последнего подключённого устройства (кнопка «Сканировать»).</summary>
        public Task RescanSelectedAsync() => _agent.RescanLastDeviceAsync();

        /// <summary>Перевести выбранный том в «только чтение» (немедленная блокировка записи).</summary>
        public string BlockDevice(string driveLetter)
        {
            if (_enforcement is null) return "Модуль принуждения недоступен.";
            var dev = Devices.FirstOrDefault(d => d.DriveLetter == driveLetter);
            bool ok = _enforcement.SetReadOnlyAsync(
                dev?.DeviceId ?? new UsbDeviceId(0, 0), dev?.Serial, driveLetter).GetAwaiter().GetResult();
            if (dev is not null && ok) dev.State = DeviceState.Blocked;
            ReloadQuarantine();
            return _enforcement.LastReadOnlyDetail ?? (ok ? "Запись ограничена." : "Мера не применена.");
        }

        /// <summary>Снять блокировку записи с тома (только после подтверждения в UI).</summary>
        public string UnblockDevice(string driveLetter)
        {
            if (_writeControl is null) return "Модуль блокировки недоступен.";
            var dev = Devices.FirstOrDefault(d => d.DriveLetter == driveLetter);
            var res = _writeControl.RestoreVolumeReadWrite(driveLetter);
            if (dev is not null && dev.State is DeviceState.Blocked) dev.State = DeviceState.Allowed;
            return res.Detail;
        }

        /// <summary>Обновить список карантина из хранилища (Q-xxxxx.json).</summary>
        public void ReloadQuarantine()
        {
            if (_quarantineStore is null) return;
            OnUi(() =>
            {
                Quarantine.Clear();
                foreach (var e in _quarantineStore.GetEntries()) Quarantine.Add(e);
                OnPropertyChanged(nameof(QuarantinedFiles));
            });
        }

        /// <summary>Дочитать NDJSON-журнал (кнопка «Обновить журнал»).</summary>
        public async Task ReloadIncidentsAsync()
        {
            var recent = await _logger.ReadRecentAsync(200);
            OnUi(() =>
            {
                Incidents.Clear();
                foreach (var r in recent) Incidents.Add(r);
            });
        }

        private void RefreshStats()
        {
            OnPropertyChanged(nameof(TotalFindings));
            OnPropertyChanged(nameof(QuarantinedFiles));
            OnPropertyChanged(nameof(DeliveredIncidents));
            OnPropertyChanged(nameof(BlockedDevices));
            OnPropertyChanged(nameof(ScanningDevices));
        }

        protected void OnPropertyChanged([CallerMemberName] string? name = null) =>
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));

        public async ValueTask DisposeAsync()
        {
            await _agent.DisposeAsync();
        }
    }

    /// <summary>Плоская строка сессии сканирования для DataGridView.</summary>
    public sealed class ScanSessionSummaryRow
    {
        public string DriveLetter { get; init; } = "";
        public string DeviceId { get; init; } = "";
        public string Serial { get; init; } = "";
        public string Stage { get; set; } = "";
        public int FilesScanned { get; set; }
        public int Findings { get; set; }
        public string Action { get; set; } = "";
        public DateTime StartedLocal { get; init; }

        public static ScanSessionSummaryRow From(ScanSessionSummary s)
        {
            var r = new ScanSessionSummaryRow
            {
                DriveLetter = s.Volume.DriveLetter,
                DeviceId = s.Volume.DeviceId.ToString(),
                Serial = s.Volume.SerialNumber ?? "—",
                StartedLocal = s.StartedAtUtc.ToLocalTime(),
            };
            r.Update(s);
            return r;
        }

        public void Update(ScanSessionSummary s)
        {
            Stage = s.Stage.ToString();
            FilesScanned = s.FilesScanned;
            Findings = s.FindingsTotal;
            Action = s.ActionApplied == EnforcementAction.None ? "—" : s.ActionApplied.ToString();
        }
    }

    /// <summary>Плоская строка таблицы «Устройства» с состоянием по паттерну State.</summary>
    public sealed class DeviceRow : INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler? PropertyChanged;

        public string DriveLetter { get; init; } = "";
        public string DeviceName { get; init; } = "";
        public string VidPid { get; init; } = "";
        public string Serial { get; init; } = "—";
        public string FileSystem { get; init; } = "";
        public UsbDeviceId DeviceId { get; init; }
        public string? SerialRaw { get; init; }

        private DeviceState _state = DeviceState.Connected;
        public DeviceState State
        {
            get => _state;
            set { if (_state != value) { _state = value; OnChanged(nameof(State)); OnChanged(nameof(StateText)); } }
        }

        private string _lastAction = "Подключено";
        public string LastAction
        {
            get => _lastAction;
            set { _lastAction = value; OnChanged(nameof(LastAction)); }
        }

        public int FilesScanned { get; set; }
        public int Findings { get; set; }

        private DateTime _lastSeenLocal = DateTime.Now;
        public DateTime LastSeenLocal
        {
            get => _lastSeenLocal;
            set { _lastSeenLocal = value; OnChanged(nameof(LastSeenLocal)); }
        }

        public string StateText => State switch
        {
            DeviceState.Connected => "Подключено",
            DeviceState.Scanning => "Сканируется",
            DeviceState.Allowed => "Разрешено",
            DeviceState.Blocked => "Заблокировано (только чтение)",
            DeviceState.Quarantined => "Карантин",
            DeviceState.Disconnected => "Отключено",
            DeviceState.Error => "Ошибка",
            _ => State.ToString(),
        };

        public static DeviceRow From(ScanSessionSummary s) => new()
        {
            DriveLetter = s.Volume.DriveLetter,
            DeviceName = $"{s.Volume.VolumeLabel ?? "USB Drive"}",
            VidPid = s.Volume.DeviceId.ToString(),
            Serial = s.Volume.SerialNumber ?? "—",
            SerialRaw = s.Volume.SerialNumber,
            FileSystem = s.Volume.FileSystem,
            DeviceId = s.Volume.DeviceId,
        };

        public void Update(ScanSessionSummary s)
        {
            FilesScanned = s.FilesScanned;
            Findings = s.FindingsTotal;
            LastSeenLocal = DateTime.Now;
            State = s.Stage switch
            {
                DeviceProcessingStage.Scanning or DeviceProcessingStage.Detected or DeviceProcessingStage.MatchingVolumes => DeviceState.Scanning,
                DeviceProcessingStage.Enforcing => DeviceState.Blocked,
                DeviceProcessingStage.Failed => DeviceState.Error,
                DeviceProcessingStage.Completed => s.FindingsTotal > 0 ? DeviceState.Quarantined : DeviceState.Allowed,
                _ => DeviceState.Connected,
            };
            if (s.FindingsTotal > 0 && s.Stage is DeviceProcessingStage.Enforcing or DeviceProcessingStage.Completed)
                LastAction = $"Найдено фрагментов: {s.FindingsTotal}, изъято в карантин";
            else if (s.Stage == DeviceProcessingStage.Scanning) LastAction = "Обход файлов…";
            else if (s.Stage == DeviceProcessingStage.Failed) LastAction = s.LastError ?? "Ошибка обработки";
            else if (s.Stage == DeviceProcessingStage.Completed) LastAction = "Проверка завершена, нарушений нет";
            OnPropertyChanged();
        }

        private void OnPropertyChanged()
        {
            OnChanged(nameof(FilesScanned));
            OnChanged(nameof(Findings));
        }

        private void OnChanged([CallerMemberName] string? name = null) =>
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }
}
