using System.ComponentModel;
using System.Runtime.CompilerServices;
using DLP.UsbController.Enums;
using DLP.UsbController.Interfaces;
using DLP.UsbController.Models;
using DLP.UsbController.Services;

namespace DLP.UsbController.ViewModels
{
    /// <summary>
    /// ViewModel окна DLP-агента: состояние агента для статус-бара/итрея,
    /// журнал активности и список инцидентов для детализированного окна.
    /// </summary>
    public sealed class AgentViewModel : INotifyPropertyChanged, IAsyncDisposable
    {
        private readonly UsbDlpAgent _agent;
        private readonly IIncidentLogger _logger;

        public event PropertyChangedEventHandler? PropertyChanged;

        public BindingList<string> ActivityLog { get; } = [];
        public BindingList<SecurityIncident> Incidents { get; } = [];
        public BindingList<ScanSessionSummaryRow> Sessions { get; } = [];

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

        public DlpPolicyConfig Policy { get; }

        public AgentViewModel(UsbDlpAgent agent, IIncidentLogger logger, DlpPolicyConfig policy)
        {
            _agent = agent;
            _logger = logger;
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
        }

        /// <summary>Маршалинг событий из фоновых потоков в UI-поток задаёт форма.</summary>
        public Action<Action>? UiMarshal { get; set; }
        private void OnUi(Action a) => (UiMarshal ?? (act => act()))(a);

        public void Start()
        {
            _agent.Start();
            IsRunning = true;
            StatusText = $"Агент работает. Политика: {Policy.DefaultAction}, центр: {Policy.CentralServerUrl}";
        }

        public async Task StopAsync()
        {
            await _agent.StopAsync();
            IsRunning = false;
            StatusText = "Агент остановлен";
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
}
