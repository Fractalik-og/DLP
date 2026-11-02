using System.ComponentModel;
using System.Runtime.CompilerServices;
using DLP.UsbController.Enums;
using DLP.UsbController.Interfaces;
using DLP.UsbController.Models;

namespace DLP.UsbController.ViewModels
{
    /// <summary>
    /// ViewModel главного окна (паттерн MVVM без сторонних библиотек).
    /// Инкапсулирует работу с IUsbAnalyzer и ICaptureStore,
    /// предоставляет UI-свойства и команды. Form общается только с этим классом.
    /// </summary>
    public class MainViewModel : INotifyPropertyChanged, IAsyncDisposable
    {
        private readonly IUsbAnalyzer _analyzer;
        private readonly ICaptureStore _store;
        private long _uiRefreshCounter;

        public event PropertyChangedEventHandler? PropertyChanged;

        // ---- свойства для привязки к элементам управления ----

        private string _statusText = "Не подключено";
        public string StatusText
        {
            get => _statusText;
            private set { _statusText = value; OnPropertyChanged(); }
        }

        private AnalyzerStatus _status;
        public AnalyzerStatus Status
        {
            get => _status;
            private set { _status = value; OnPropertyChanged(); }
        }

        private bool _isBusy;
        public bool IsBusy
        {
            get => _isBusy;
            private set { _isBusy = value; OnPropertyChanged(); }
        }

        public bool CanConnect => !IsBusy && Status == AnalyzerStatus.Disconnected;
        public bool CanStartCapture => !IsBusy && Status is AnalyzerStatus.Ready or AnalyzerStatus.Paused;
        public bool CanStopCapture => !IsBusy && Status is AnalyzerStatus.Capturing or AnalyzerStatus.Paused;

        public CaptureSettings Settings { get; } = new();

        /// <summary>Пакеты для отображения в DataGridView (обновляются порциями).</summary>
        public BindingList<UsbPacketRow> VisiblePackets { get; } = new();

        // ---- команды (вызываются обработчиками событий формы) ----

        public async Task ConnectAsync()
        {
            IsBusy = true; NotifyCommandsChanged();
            try
            {
                await _analyzer.ConnectAsync();
            }
            finally
            {
                IsBusy = false; NotifyCommandsChanged();
            }
        }

        public async Task DisconnectAsync()
        {
            IsBusy = true; NotifyCommandsChanged();
            try
            {
                await _analyzer.DisconnectAsync();
            }
            finally
            {
                IsBusy = false; NotifyCommandsChanged();
            }
        }

        public async Task StartCaptureAsync()
        {
            IsBusy = true; NotifyCommandsChanged();
            try
            {
                VisiblePackets.Clear();
                _store.Clear();
                await _analyzer.StartCaptureAsync(Settings.Clone());
            }
            finally
            {
                IsBusy = false; NotifyCommandsChanged();
            }
        }

        public async Task StopCaptureAsync()
        {
            IsBusy = true; NotifyCommandsChanged();
            try
            {
                await _analyzer.StopCaptureAsync();
            }
            finally
            {
                IsBusy = false; NotifyCommandsChanged();
            }
        }

        public async Task TogglePauseAsync()
        {
            await _analyzer.SetPausedAsync(Status != AnalyzerStatus.Paused);
        }

        public async Task ExportAsync(string filePath)
        {
            await _analyzer.ExportAsync(filePath);
        }

        // ---- конструктор и обработка событий анализатора ----

        public MainViewModel(IUsbAnalyzer analyzer, ICaptureStore store)
        {
            _analyzer = analyzer ?? throw new ArgumentNullException(nameof(analyzer));
            _store = store ?? throw new ArgumentNullException(nameof(store));

            _analyzer.StatusChanged += OnStatusChanged;
            _analyzer.PacketCaptured += OnPacketCaptured;
        }

        private void OnStatusChanged(object? sender, AnalyzerStatusChangedEventArgs e)
        {
            Status = e.NewStatus;
            StatusText = e.Message is null ? e.NewStatus.ToString() : $"{e.NewStatus}: {e.Message}";
            NotifyCommandsChanged();
        }

        private void OnPacketCaptured(object? sender, PacketCapturedEventArgs e)
        {
            var packet = e.Packet; // копия: by-ref нельзя передать из свойства события
            _store.Add(in packet);

            // Обновляем UI не чаще, чем каждый N-й пакет — иначе DataGridView «ляжет».
            if (++_uiRefreshCounter % 20 != 0) return;

            var row = UsbPacketRow.From(in packet);
            VisiblePackets.Add(row);

            const int maxVisibleRows = 5000;
            while (VisiblePackets.Count > maxVisibleRows)
                VisiblePackets.RemoveAt(0);
        }

        private void NotifyCommandsChanged()
        {
            OnPropertyChanged(nameof(CanConnect));
            OnPropertyChanged(nameof(CanStartCapture));
            OnPropertyChanged(nameof(CanStopCapture));
        }

        protected void OnPropertyChanged([CallerMemberName] string? name = null) =>
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));

        public async ValueTask DisposeAsync()
        {
            _analyzer.PacketCaptured -= OnPacketCaptured;
            _analyzer.StatusChanged -= OnStatusChanged;
            await _analyzer.DisconnectAsync();
            _analyzer.Dispose();
        }
    }

    /// <summary>
    /// Строка таблицы пакетов для привязки к DataGridView
    /// (структуру UsbPacket удобно показывать через плоский класс).
    /// </summary>
    public sealed class UsbPacketRow
    {
        public long Seq { get; init; }
        public string Time { get; init; } = string.Empty;
        public string Type { get; init; } = string.Empty;
        public string Direction { get; init; } = string.Empty;
        public int Address { get; init; }
        public int Endpoint { get; init; }
        public int Length { get; init; }
        public string PayloadHex { get; init; } = string.Empty;
        public bool HasError { get; init; }

        public static UsbPacketRow From(in UsbPacket p) => new()
        {
            Seq = p.SequenceNumber,
            Time = p.Time.ToString(@"hh\:mm\:ss\.FFFFFF"),
            Type = p.Type.ToString(),
            Direction = p.Direction switch
            {
                TransferDirection.HostToDevice => "H→D",
                TransferDirection.DeviceToHost => "D→H",
                _ => "—"
            },
            Address = p.DeviceAddress,
            Endpoint = p.EndpointNumber,
            Length = p.Payload.Length,
            PayloadHex = p.PayloadHex,
            HasError = p.HasCrcError
        };
    }
}
