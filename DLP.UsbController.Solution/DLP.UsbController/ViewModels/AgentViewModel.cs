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
    /// одна таблица подключённых носителей и содержимое карантина.
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
                while (ActivityLog.Count > 300) ActivityLog.RemoveAt(ActivityLog.Count - 1);
            });

            _agent.SessionUpdated += (_, s) => OnUi(() =>
            {
                // Одна таблица устройств вместо двух (сессии + устройства).
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
            StatusText = $"Агент работает. Режим: {Policy.DefaultAction.Text()}, запуск: {(IsElevated ? "от администратора" : "обычный")}";
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
                dev?.DeviceId ?? new UsbDeviceId(0, 0), dev?.SerialRaw, driveLetter).GetAwaiter().GetResult();
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

    /// <summary>
    /// Плоская строка таблицы «Носители»: одно устройство = одна строка,
    /// состояние — по паттерну State (русский текст из [Description]).
    /// </summary>
    public sealed class DeviceRow : INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler? PropertyChanged;

        public string DriveLetter { get; init; } = "";
        public UsbDeviceId DeviceId { get; init; }
        public string? SerialRaw { get; init; }

        private DeviceState _state = DeviceState.Connected;
        public DeviceState State
        {
            get => _state;
            set { if (_state != value) { _state = value; OnChanged(nameof(State)); OnChanged(nameof(StatusText)); } }
        }

        private string _lastAction = "Подключено";
        public string LastAction
        {
            get => _lastAction;
            set { _lastAction = value; OnChanged(nameof(LastAction)); }
        }

        public int FilesScanned { get; set; }
        public int Findings { get; set; }

        // ---- готовые к показу значения (столбцы таблицы) ----
        public string StatusText => State.Text();
        public string FindingsTextRu => Findings > 0 ? Findings.ToString() : "—";
        public string StartedText { get; set; } = "";

        public static DeviceRow From(ScanSessionSummary s) => new()
        {
            DriveLetter = s.Volume.DriveLetter,
            DeviceId = s.Volume.DeviceId,
            SerialRaw = s.Volume.SerialNumber,
            StartedText = s.StartedAtUtc.ToLocalTime().ToString("HH:mm:ss"),
        };

        public void Update(ScanSessionSummary s)
        {
            FilesScanned = s.FilesScanned;
            Findings = s.FindingsTotal;
            State = s.Stage switch
            {
                DeviceProcessingStage.Scanning or DeviceProcessingStage.Detected or DeviceProcessingStage.MatchingVolumes => DeviceState.Scanning,
                DeviceProcessingStage.Enforcing => DeviceState.Blocked,
                DeviceProcessingStage.Failed => DeviceState.Error,
                DeviceProcessingStage.Completed => s.FindingsTotal > 0 ? DeviceState.Quarantined : DeviceState.Allowed,
                _ => DeviceState.Connected,
            };
            if (s.FindingsTotal > 0 && s.Stage is DeviceProcessingStage.Enforcing or DeviceProcessingStage.Completed)
                LastAction = $"Изъято в карантин: {s.FindingsTotal}";
            else if (s.Stage == DeviceProcessingStage.Scanning) LastAction = "Обход файлов…";
            else if (s.Stage == DeviceProcessingStage.Failed) LastAction = s.LastError ?? "Ошибка обработки";
            else if (s.Stage == DeviceProcessingStage.Completed) LastAction = "Нарушений нет";

            OnChanged(nameof(StatusText));
            OnChanged(nameof(FindingsTextRu));
        }

        private void OnChanged([CallerMemberName] string? name = null) =>
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }
}
