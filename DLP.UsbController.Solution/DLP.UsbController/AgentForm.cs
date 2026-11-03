using DLP.UsbController.Enums;
using DLP.UsbController.Interfaces;
using DLP.UsbController.Models;
using DLP.UsbController.Services;
using DLP.UsbController.ViewModels;

namespace DLP.UsbController
{
    /// <summary>
    /// Окно DLP-агента (компактная версия): одна таблица носителей, журнал активности,
    /// карантин и статус-бар. Все подписи в интерфейсе — на русском.
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
        private ContextMenuStrip _trayMenu = null!;
        private DataGridView _gridDevices = null!, _gridQuarantine = null!;
        private ListBox _listActivity = null!;
        private Button _btnStart = null!, _btnStop = null!, _btnLog = null!, _btnOpenQ = null!, _btnRefreshQ = null!;
        private StatusStrip _status = null!;
        private ToolStripStatusLabel _lblStatus = null!, _lblStats = null!;
        private TabControl _tabs = null!;
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
            catch (ObjectDisposedException) { /* окно закрылось — игнорируем */ }
            catch (InvalidOperationException) { /* дескриптор уничтожен — игнорируем */ }
        }

        protected override void OnHandleCreated(EventArgs e)
        {
            base.OnHandleCreated(e);

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

        // ============================ ИНТЕРФЕЙС ============================

        private void BuildUi()
        {
            Text = "DLP-агент: контроль USB-накопителей";
            StartPosition = FormStartPosition.CenterScreen;
            ClientSize = new Size(860, 520);
            MinimumSize = new Size(640, 400);

            var topPanel = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 38, Padding = new Padding(6, 6, 6, 2) };
            _btnStart = new Button { Text = "Запустить", AutoSize = true };
            _btnStop = new Button { Text = "Остановить", AutoSize = true };
            _btnLog = new Button { Text = "Журнал инцидентов", AutoSize = true };
            topPanel.Controls.AddRange([_btnStart, _btnStop, _btnLog]);

            _tabs = new TabControl { Dock = DockStyle.Fill };
            var tabDevices = new TabPage("Носители") { Padding = new Padding(3) };
            var tabQuarantine = new TabPage("Карантин") { Padding = new Padding(3) };
            var tabActivity = new TabPage("Журнал работы") { Padding = new Padding(3) };
            _tabs.TabPages.AddRange([tabDevices, tabQuarantine, tabActivity]);

            // --- вкладка «Носители»: одна таблица + кнопки мер ---
            _gridDevices = NewGrid(_vm.Devices);
            AddCols(_gridDevices,
                ("DriveLetter", "Том", 90),
                ("StatusText", "Состояние", 170),
                ("FindingsTextRu", "Находок", 90),
                ("LastAction", "Действие", 320),
                ("StartedText", "Время", 90));

            var devButtons = new FlowLayoutPanel { Dock = DockStyle.Bottom, Height = 34, Padding = new Padding(4) };
            var btnRescan = new Button { Text = "Пересканировать", AutoSize = true };
            var btnBlock = new Button { Text = "Блокировать запись", AutoSize = true };
            var btnUnblock = new Button { Text = "Разблокировать", AutoSize = true };
            btnRescan.Click += async (_, _) => await RescanAsync();
            btnBlock.Click += (_, _) => RunOnDevice(_vm.BlockDevice);
            btnUnblock.Click += (_, _) => RunOnDevice(_vm.UnblockDevice);
            devButtons.Controls.AddRange([btnRescan, btnBlock, btnUnblock]);

            tabDevices.Controls.Add(_gridDevices);
            tabDevices.Controls.Add(devButtons);

            // --- вкладка «Карантин» ---
            _gridQuarantine = NewGrid(_vm.Quarantine);
            AddCols(_gridQuarantine,
                ("Id", "Номер", 90),
                ("OriginalName", "Файл", 220),
                ("StoredFileName", "В карантине", 200),
                ("SizeText", "Размер", 80),
                ("QuarantinedLocalText", "Изъят", 120));

            var qButtons = new FlowLayoutPanel { Dock = DockStyle.Bottom, Height = 34, Padding = new Padding(4) };
            _btnOpenQ = new Button { Text = "Открыть папку карантина", AutoSize = true };
            _btnRefreshQ = new Button { Text = "Обновить список", AutoSize = true };
            _btnOpenQ.Click += (_, _) => OpenQuarantineFolder();
            _btnRefreshQ.Click += (_, _) => _vm.ReloadQuarantine();
            qButtons.Controls.AddRange([_btnOpenQ, _btnRefreshQ]);

            tabQuarantine.Controls.Add(_gridQuarantine);
            tabQuarantine.Controls.Add(qButtons);

            // --- вкладка «Журнал работы» ---
            _listActivity = new ListBox
            {
                Dock = DockStyle.Fill,
                IntegralHeight = false,
                Font = new Font("Consolas", 9f),
                DataSource = _vm.ActivityLog,
            };
            tabActivity.Controls.Add(_listActivity);

            _status = new StatusStrip();
            _lblStatus = new ToolStripStatusLabel("Агент остановлен") { Spring = true, TextAlign = ContentAlignment.MiddleLeft };
            _lblStats = new ToolStripStatusLabel("") { AutoSize = true };
            _status.Items.AddRange([_lblStatus, _lblStats]);

            Controls.Add(_tabs);
            Controls.Add(topPanel);
            Controls.Add(_status);
        }

        private static DataGridView NewGrid(object dataSource) => new()
        {
            Dock = DockStyle.Fill,
            ReadOnly = true,
            AllowUserToAddRows = false,
            RowHeadersVisible = false,
            AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.None,
            SelectionMode = DataGridViewSelectionMode.FullRowSelect,
            AllowUserToResizeRows = false,
            DataSource = dataSource,
        };

        private static void AddCols(DataGridView grid, params (string Prop, string Header, int Width)[] cols)
        {
            grid.Columns.Clear();
            foreach (var (prop, header, width) in cols)
            {
                int idx = grid.Columns.Add(prop, header);
                if (idx >= 0) grid.Columns[idx].Width = width;
            }
        }

        private void Bind()
        {
            _btnStart.Click += (_, _) => _vm.Start();
            _btnStop.Click += async (_, _) => await _vm.StopAsync();
            _btnLog.Click += (_, _) => ShowLog();

            _vm.PropertyChanged += (_, e) => MarshalToUi(() => ApplyVmState(e.PropertyName));
            ApplyVmState(null);
        }

        private void ApplyVmState(string? prop)
        {
            _btnStart.Enabled = _vm.CanStart;
            _btnStop.Enabled = _vm.CanStop;
            _lblStatus.Text = _vm.StatusText;
            _lblStats.Text = $"Инцидентов: {_vm.Incidents.Count} · Находок: {_vm.TotalFindings} · В карантине: {_vm.QuarantinedFiles}";

            _tray?.Icon = _vm.IsRunning ? SystemIcons.Shield : SystemIcons.Warning;
            _tray?.Text = _vm.IsRunning ? "DLP-агент: наблюдение включено" : "DLP-агент: остановлен";
        }

        // ============================ ДЕЙСТВИЯ ============================

        private string SelectedDrive() =>
            _gridDevices.CurrentRow?.DataBoundItem is DeviceRow r ? r.DriveLetter : "";

        private void RunOnDevice(Func<string, string> action)
        {
            string drive = SelectedDrive();
            if (string.IsNullOrEmpty(drive))
            {
                Info("Сначала выберите строку с носителем.");
                return;
            }
            Info(action(drive));
        }

        private async Task RescanAsync()
        {
            try
            {
                await _vm.RescanSelectedAsync();
            }
            catch (InvalidOperationException)
            {
                Info("Устройства ещё не подключались.");
            }
        }

        private void OpenQuarantineFolder()
        {
            string dir = _vm.QuarantineDirectory;
            try
            {
                if (!System.IO.Directory.Exists(dir)) System.IO.Directory.CreateDirectory(dir);
                var psi = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = dir,
                    UseShellExecute = OperatingSystem.IsWindows(),
                };
                if (!OperatingSystem.IsWindows())
                {
                    // вне Windows — просто открываем путь в проводнике ОС песочницы, если он есть
                    psi.FileName = "xdg-open";
                    psi.ArgumentList.Add(dir);
                }
                System.Diagnostics.Process.Start(psi);
            }
            catch (Exception ex)
            {
                Info($"Не удалось открыть папку: {ex.Message}\nПуть: {dir}");
            }
        }

        private void Info(string text) =>
            MessageBox.Show(this, text, "DLP-агент", MessageBoxButtons.OK, MessageBoxIcon.Information);

        // ============================ ТРЕЙ / ЖУРНАЛ ============================

        private void InitTray()
        {
            _trayMenu = new ContextMenuStrip();
            var miLog = new ToolStripMenuItem("Журнал событий…");
            miLog.Click += (_, _) => { ShowWindow(); ShowLog(); };
            var miStart = new ToolStripMenuItem("Запустить наблюдение");
            miStart.Click += (_, _) => _vm.Start();
            var miStop = new ToolStripMenuItem("Остановить");
            miStop.Click += async (_, _) => await _vm.StopAsync();
            var miExit = new ToolStripMenuItem("Выход");
            miExit.Click += (_, _) => CloseAgent();

            _trayMenu.Items.AddRange([miLog, new ToolStripSeparator(), miStart, miStop, new ToolStripSeparator(), miExit]);

            _tray = new NotifyIcon
            {
                Icon = SystemIcons.Warning,
                Text = "DLP-агент: остановлен",
                Visible = true,
                ContextMenuStrip = _trayMenu,
            };
            _tray.DoubleClick += (_, _) => { ShowWindow(); ShowLog(); };

            // Стартуем агент сразу, чтобы конвейер «обнаружение → скан → карантин» был виден.
            _vm.Start();
            _tray.BalloonTipTitle = "DLP-агент";
            _tray.BalloonTipText = "Наблюдение за USB-накопителями запущено.";
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
            // Крестик ≠ выход: сворачиваемся в трей.
            if (!_reallyClose && e.CloseReason == CloseReason.UserClosing)
            {
                e.Cancel = true;
                Hide();
                _tray.BalloonTipTitle = "DLP-агент";
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
            _tray.Visible = false;
            _tray.Dispose();
            _trayMenu.Dispose();
            GC.SuppressFinalize(_logger); // логгер живёт дольше окна — закрывает Program
            Close();
        }

        // ============================ СОСТАВ OKНА ============================

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
            var quarantineStore = new QuarantineStore(quarantine);
            var writeControl = new UsbWriteControl();
            var enforcement = new RegistryEnforcementModule(effectivePolicy, writeControl, quarantineStore);
            var agent = new UsbDlpAgent(watcher, scanner, enforcement, logger, effectivePolicy);
            var vm = new AgentViewModel(agent, logger, effectivePolicy, quarantineStore, writeControl, enforcement);
            return new AgentForm(vm, logger);
        }
    }
}
