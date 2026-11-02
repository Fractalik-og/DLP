using DLP.UsbController.Enums;
using DLP.UsbController.Interfaces;
using DLP.UsbController.Models;
using DLP.UsbController.Services;
using DLP.UsbController.ViewModels;

namespace DLP.UsbController
{
    /// <summary>
    /// Главное окно USB-анализатора.
    /// Layout: панель инструментов сверху, таблица пакетов в центре, статус-бар снизу.
    /// </summary>
    public partial class MainForm : Form
    {
        private readonly MainViewModel _viewModel;

        // Элементы управления (создаются в Designer)
        private ToolStrip _toolStrip = null!;
        private ToolStripButton _btnConnect = null!;
        private ToolStripButton _btnDisconnect = null!;
        private ToolStripSeparator _sep1 = null!;
        private ToolStripButton _btnStart = null!;
        private ToolStripButton _btnPause = null!;
        private ToolStripButton _btnStop = null!;
        private ToolStripSeparator _sep2 = null!;
        private ToolStripButton _btnExport = null!;
        private DataGridView _grid = null!;
        private StatusStrip _statusStrip = null!;
        private ToolStripStatusLabel _lblStatus = null!;

        public MainForm()
        {
            // Внедрение зависимостей: для production здесь будет DI-контейнер (Microsoft.Extensions.DependencyInjection).
            IUsbAnalyzer analyzer = new EmulatedUsbAnalyzer();
            ICaptureStore store = new RingBufferCaptureStore();
            _viewModel = new MainViewModel(analyzer, store);

            // Элементы управления создаются до InitializeComponent,
            // т.к. Designer добавляет их в Controls.
            BuildToolbar();
            BuildGrid();
            BuildStatusBar();

            InitializeComponent();
            BindViewModel();
        }

        private void BuildToolbar()
        {
            _toolStrip = new ToolStrip { GripStyle = ToolStripGripStyle.Hidden, Dock = DockStyle.Top };

            _btnConnect = new ToolStripButton("Подключить") { DisplayStyle = ToolStripItemDisplayStyle.Text };
            _btnDisconnect = new ToolStripButton("Отключить") { DisplayStyle = ToolStripItemDisplayStyle.Text };
            _sep1 = new ToolStripSeparator();
            _btnStart = new ToolStripButton("▶ Старт захвата") { DisplayStyle = ToolStripItemDisplayStyle.Text };
            _btnPause = new ToolStripButton("⏸ Пауза") { DisplayStyle = ToolStripItemDisplayStyle.Text };
            _btnStop = new ToolStripButton("⏹ Стоп") { DisplayStyle = ToolStripItemDisplayStyle.Text };
            _sep2 = new ToolStripSeparator();
            _btnExport = new ToolStripButton("Экспорт…") { DisplayStyle = ToolStripItemDisplayStyle.Text };

            _toolStrip.Items.AddRange([_btnConnect, _btnDisconnect, _sep1, _btnStart, _btnPause, _btnStop, _sep2, _btnExport]);

            _btnConnect.Click += async (_, _) => await _viewModel.ConnectAsync();
            _btnDisconnect.Click += async (_, _) => await _viewModel.DisconnectAsync();
            _btnStart.Click += async (_, _) => await _viewModel.StartCaptureAsync();
            _btnPause.Click += async (_, _) => await _viewModel.TogglePauseAsync();
            _btnStop.Click += async (_, _) => await _viewModel.StopCaptureAsync();
            _btnExport.Click += OnExportClick;
        }

        private void BuildGrid()
        {
            _grid = new DataGridView
            {
                Dock = DockStyle.Fill,
                ReadOnly = true,
                AllowUserToAddRows = false,
                AllowUserToDeleteRows = false,
                RowHeadersVisible = false,
                AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill,
                SelectionMode = DataGridViewSelectionMode.FullRowSelect,
                VirtualMode = false,
                BackgroundColor = Color.White
            };
            _grid.DataSource = _viewModel.VisiblePackets;
        }

        private void BuildStatusBar()
        {
            _statusStrip = new StatusStrip { Dock = DockStyle.Bottom };
            _lblStatus = new ToolStripStatusLabel(_viewModel.StatusText) { Spring = true, TextAlign = ContentAlignment.MiddleLeft };
            _statusStrip.Items.Add(_lblStatus);
        }

        private void BindViewModel()
        {
            _viewModel.PropertyChanged += (_, e) =>
            {
                // События приходят из фоновых потоков — маршалим в UI-поток.
                // BeginInvoke недопустим до создания дескриптора окна, поэтому
                // проверяем IsHandleCreated и выполняем напрямую в UI-потоке.
                if (IsHandleCreated && InvokeRequired)
                {
                    try { BeginInvoke(() => UpdateUi(e.PropertyName)); }
                    catch (ObjectDisposedException) { }
                    catch (InvalidOperationException) { }
                }
                else UpdateUi(e.PropertyName);
            };

            void UpdateUi(string? prop)
            {
                switch (prop)
                {
                    case nameof(MainViewModel.StatusText):
                        _lblStatus.Text = _viewModel.StatusText;
                        break;
                    case nameof(MainViewModel.CanConnect):
                        _btnConnect.Enabled = _viewModel.CanConnect;
                        _btnDisconnect.Enabled = _viewModel.Status != AnalyzerStatus.Disconnected;
                        break;
                    case nameof(MainViewModel.CanStartCapture):
                        _btnStart.Enabled = _viewModel.CanStartCapture;
                        break;
                    case nameof(MainViewModel.CanStopCapture):
                        _btnStop.Enabled = _viewModel.CanStopCapture;
                        _btnPause.Enabled = _viewModel.CanStopCapture;
                        break;
                }
            }

            UpdateUi(null); // первичная инициализация кнопок
        }

        private async void OnExportClick(object? sender, EventArgs e)
        {
            using var dlg = new SaveFileDialog
            {
                Filter = "CSV (*.csv)|*.csv|Все файлы (*.*)|*.*",
                FileName = $"usb_capture_{DateTime.Now:yyyyMMdd_HHmmss}.csv"
            };
            if (dlg.ShowDialog() == DialogResult.OK)
                await _viewModel.ExportAsync(dlg.FileName);
        }

        protected override void OnFormClosed(FormClosedEventArgs e)
        {
            // Асинхронную очистку запускаем «огонь и забудь»: к моменту закрытия окна
            // это последний шанс корректно остановить анализатор.
            _ = _viewModel.DisposeAsync().AsTask();
            base.OnFormClosed(e);
        }
    }
}
