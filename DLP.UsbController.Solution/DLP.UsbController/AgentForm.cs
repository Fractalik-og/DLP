using DLP.UsbController.Enums;
using DLP.UsbController.Interfaces;
using DLP.UsbController.Models;
using DLP.UsbController.Services;
using DLP.UsbController.ViewModels;

namespace DLP.UsbController
{
    /// <summary>
    /// Главное окно DLP-агента контроля съёмных USB-накопителей.
    ///  - работает в системном трее (NotifyIcon) с индикатором состояния;
    ///  - показывает активные сессии сканирования, журнал активности, статистику;
    ///  - детализированный журнал инцидентов открывается двойным кликом по трею/кнопкой.
    /// </summary>
    public sealed class AgentForm : Form
    {
        private readonly AgentViewModel _vm;
        private readonly IIncidentLogger _logger;

        // События агента приходят из фоновых потоков (WMI, Task.Run), в том числе
        // ДО создания дескриптора окна — Invoke/BeginInvoke в этот момент бросает
        // InvalidOperationException. Поэтому маршалинг откладывается до OnHandleCreated.
        private readonly Queue<Action> _pendingUiActions = new();
        private bool _uiReady;
        private readonly object _pendingLock = new();

        private NotifyIcon _tray = null!;
        private ToolStripMenuItem _miShowLog = null!;
        private ContextMenuStrip _trayMenu = null!;
        private DataGridView _gridSessions = null!;
        private ListBox _listActivity = null!;
        private Button _btnStart = null!, _btnStop = null!, _btnLog = null!;
        private StatusStrip _status = null!;
        private ToolStripStatusLabel _lblStatus = null!, _lblStats = null!;
        private bool _reallyClose;

        public AgentForm(AgentViewModel vm, IIncidentLogger logger)
        {
            _vm = vm;
            _logger = logger;
            // Безопасный маршалинг в UI-поток: если дескриптор окна ещё не создан,
            // действие ставится в очередь и будет выполнено в OnHandleCreated.
            _vm.UiMarshal = MarshalToUi;

            BuildUi();
            Bind();
        }

        /// <summary>
        /// Маршалинг делегата в поток UI. Устраняет гонку: события агента могут
        /// прийти раньше, чем у формы появится оконный дескриптор (Handle).
        /// </summary>
        private void MarshalToUi(Action action)
        {
            if (action is null) return;

            lock (_pendingLock)
            {
                if (!_uiReady || !IsHandleCreated)
                {
                    _pendingUiActions.Enqueue(action);
                    return;
                }
            }

            try
            {
                if (InvokeRequired) BeginInvoke(action);
                else action();
            }
            catch (ObjectDisposedException)
            {
                // Окно закрылось во время асинхронного события — игнорируем.
            }
            catch (InvalidOperationException)
            {
                // Дескриптор уничтожен между проверкой и вызовом — игнорируем.
            }
        }

        protected override void OnHandleCreated(EventArgs e)
        {
            base.OnHandleCreated(e);

            // Дескриптор создан — можно безопасно выполнять накопленные события
            // и инициализировать трей/запуск агента (InitTray вызывает _vm.Start()).
            InitTray();

            List<Action> pending;
            lock (_pendingLock)
            {
                _uiReady = true;
                pending = new List<Action>(_pendingUiActions);
                _pendingUiActions.Clear();
            }
            foreach (var a in pending)
            {
                try { a(); } catch { /* не роняем окно из-за устаревшего события */ }
            }
        }

        private void BuildUi()
        {
            Text = "DLP USB Agent — контроль съёмных носителей";
            StartPosition = FormStartPosition.CenterScreen;
            ClientSize = new Size(980, 620);
            MinimumSize = new Size(720, 460);

            var topPanel = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 40, Padding = new Padding(6) };
            _btnStart = new Button { Text = "▶ Запустить агент", AutoSize = true };
            _btnStop = new Button { Text = "⏹ Остановить", AutoSize = true };
            _btnLog = new Button { Text = "📄 Журнал инцидентов", AutoSize = true };
            topPanel.Controls.AddRange([_btnStart, _btnStop, _btnLog]);

            var split = new SplitContainer
            {
                Dock = DockStyle.Fill,
                Orientation = Orientation.Vertical,
                SplitterDistance = 560,
            };

            _gridSessions = new DataGridView
            {
                Dock = DockStyle.Fill,
                ReadOnly = true,
                AllowUserToAddRows = false,
                RowHeadersVisible = false,
                AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill,
                SelectionMode = DataGridViewSelectionMode.FullRowSelect,
                DataSource = _vm.Sessions,
            };
            ConfigureSessionColumns();

            var actLabel = new Label { Text = "Журнал активности агента:", Dock = DockStyle.Top, Height = 22, Padding = new Padding(4, 4, 0, 0) };
            _listActivity = new ListBox { Dock = DockStyle.Fill, IntegralHeight = false, Font = new Font("Consolas", 9f) };
            _listActivity.DataSource = _vm.ActivityLog;

            split.Panel1.Controls.Add(_gridSessions);
            split.Panel2.Controls.Add(_listActivity);
            split.Panel2.Controls.Add(actLabel);

            _status = new StatusStrip();
            _lblStatus = new ToolStripStatusLabel("Агент остановлен") { Spring = true, TextAlign = ContentAlignment.MiddleLeft };
            _lblStats = new ToolStripStatusLabel("") { AutoSize = true };
            _status.Items.AddRange([_lblStatus, _lblStats]);

            Controls.Add(split);
            Controls.Add(topPanel);
            Controls.Add(_status);
        }

        private void ConfigureSessionColumns()
        {
            _gridSessions.Columns.Clear();
            AddCol(nameof(ScanSessionSummaryRow.DriveLetter), "Том");
            AddCol(nameof(ScanSessionSummaryRow.DeviceId), "VID/PID");
            AddCol(nameof(ScanSessionSummaryRow.Serial), "SN");
            AddCol(nameof(ScanSessionSummaryRow.Stage), "Стадия");
            AddCol(nameof(ScanSessionSummaryRow.FilesScanned), "Файлов");
            AddCol(nameof(ScanSessionSummaryRow.Findings), "Находок");
            AddCol(nameof(ScanSessionSummaryRow.Action), "Мера");
            AddCol(nameof(ScanSessionSummaryRow.StartedLocal), "Начало");
        }

        private void AddCol(string prop, string header)
        {
            int idx = _gridSessions.Columns.Add(prop, header);
            if (idx >= 0) _gridSessions.Columns[idx].FillWeight = header.Length * 12 + 30;
        }

        private void Bind()
        {
            _btnStart.Click += (_, _) => { _vm.Start(); };
            _btnStop.Click += async (_, _) => await _vm.StopAsync();
            _btnLog.Click += (_, _) => ShowLog();

            _vm.PropertyChanged += (_, e) =>
            {
                // Тот же безопасный путь: без прямого BeginInvoke до создания Handle.
                MarshalToUi(() => ApplyVmState(e.PropertyName));
            };
            ApplyVmState(null);
        }

        private void ApplyVmState(string? prop)
        {
            _btnStart.Enabled = _vm.CanStart;
            _btnStop.Enabled = _vm.CanStop;
            _lblStatus.Text = _vm.StatusText;
            _lblStats.Text = $"Инцидентов: {_vm.Incidents.Count} · Находок: {_vm.TotalFindings} · " +
                             $"В карантине: {_vm.QuarantinedFiles} · Отправлено на центр: {_vm.DeliveredIncidents}";

            _tray?.Icon = _vm.IsRunning ? SystemIcons.Shield : SystemIcons.Warning;
            _tray?.Text = _vm.IsRunning
                ? "DLP USB Agent: мониторинг активен"
                : "DLP USB Agent: остановлен";
        }

        private void InitTray()
        {
            _trayMenu = new ContextMenuStrip();
            _miShowLog = new ToolStripMenuItem("Журнал событий…");
            _miShowLog.Click += (_, _) => { ShowWindow(); ShowLog(); };
            var miStart = new ToolStripMenuItem("Запустить мониторинг");
            miStart.Click += (_, _) => _vm.Start();
            var miStop = new ToolStripMenuItem("Остановить");
            miStop.Click += async (_, _) => await _vm.StopAsync();
            var miExit = new ToolStripMenuItem("Выход");
            miExit.Click += (_, _) => CloseAgent();

            _trayMenu.Items.AddRange([_miShowLog, new ToolStripSeparator(), miStart, miStop, new ToolStripSeparator(), miExit]);

            _tray = new NotifyIcon
            {
                Icon = SystemIcons.Warning,
                Text = "DLP USB Agent: остановлен",
                Visible = true,
                ContextMenuStrip = _trayMenu,
            };
            _tray.DoubleClick += (_, _) => { ShowWindow(); ShowLog(); };

            // В демо-режиме (не Windows) сразу запускаем агента, чтобы трей «ожил».
            _vm.Start();
            _tray.BalloonTipTitle = "DLP USB Agent";
            _tray.BalloonTipText = "Мониторинг съёмных USB-накопителей запущен.";
            _tray.ShowBalloonTip(3000);
        }

        private void ShowWindow()
        {
            Show();
            WindowState = FormWindowState.Normal;
            Activate();
        }

        private IncidentLogForm? _logForm;
        private void ShowLog()
        {
            if (_logForm is { IsDisposed: false }) { _logForm.BringToFront(); return; }
            _logForm = new IncidentLogForm(_vm);
            _logForm.Show(this);
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            // Крестик ≠ выход: сворачиваемся в трей (классика агентов безопасности).
            if (!_reallyClose && e.CloseReason == CloseReason.UserClosing)
            {
                e.Cancel = true;
                Hide();
                _tray.BalloonTipTitle = "DLP USB Agent";
                _tray.BalloonTipText = "Агент продолжает работу в системном трее.";
                _tray.ShowBalloonTip(2000);
                return;
            }
            base.OnFormClosing(e);
        }

        private void CloseAgent()
        {
            _reallyClose = true;
            _vm.StopAsync().GetAwaiter().GetResult();
            DisposeAgentResources();
            Close();
        }

        private void DisposeAgentResources()
        {
            _tray.Visible = false;
            _tray.Dispose();
            _trayMenu.Dispose();
            GC.SuppressFinalize(_logger); // логгер живёт дольше окна — закрывает Program
        }

        public static AgentForm CreateForDemo(DlpPolicyConfig policy, IIncidentLogger logger)
        {
            string demoRoot = Path.Combine(Path.GetTempPath(), "dlp_demo_flash");
            string quarantine = string.IsNullOrWhiteSpace(policy.QuarantineDirectory) || policy.QuarantineDirectory.StartsWith(@"C:\")
                ? Path.Combine(Path.GetTempPath(), "dlp_quarantine")
                : policy.QuarantineDirectory;
            var effectivePolicy = new DlpPolicyConfig
            {
                DefaultAction = EnforcementAction.QuarantineFiles,
                QuarantineDirectory = quarantine,
                CentralServerUrl = policy.CentralServerUrl,
                KeywordDictionaries = policy.KeywordDictionaries,
                MaxFileScanSizeMb = policy.MaxFileScanSizeMb,
                WhitelistedDeviceIds = policy.WhitelistedDeviceIds,
                WhitelistedSerialNumbers = policy.WhitelistedSerialNumbers,
            };

            IRemovableDeviceWatcher watcher = OperatingSystem.IsWindows()
                ? new WmiRemovableDeviceWatcher()
                : new SimulatedRemovableDeviceWatcher(demoRoot);

            var scanner = new ContentScanner(effectivePolicy);
            var enforcement = new RegistryEnforcementModule(effectivePolicy);
            var agent = new UsbDlpAgent(watcher, scanner, enforcement, logger, effectivePolicy);
            var vm = new AgentViewModel(agent, logger, effectivePolicy);
            return new AgentForm(vm, logger);
        }
    }
}
