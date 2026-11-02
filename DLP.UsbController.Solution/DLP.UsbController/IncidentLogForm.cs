using DLP.UsbController.Models;
using DLP.UsbController.ViewModels;

namespace DLP.UsbController
{
    /// <summary>
    /// Детализированный журнал событий агента: список инцидентов (NDJSON-записи)
    /// с раскрытием находок и карантина по выбранной записи.
    /// </summary>
    public sealed class IncidentLogForm : Form
    {
        private readonly AgentViewModel _vm;
        private readonly SplitContainer _split;
        private readonly DataGridView _gridIncidents;
        private readonly TextBox _details;

        public IncidentLogForm(AgentViewModel vm)
        {
            _vm = vm;

            Text = "Журнал инцидентов DLP-агента";
            StartPosition = FormStartPosition.CenterParent;
            Width = 1000;
            Height = 640;

            _split = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Horizontal, SplitterDistance = 320 };

            _gridIncidents = new DataGridView
            {
                Dock = DockStyle.Fill,
                ReadOnly = true,
                AllowUserToAddRows = false,
                RowHeadersVisible = false,
                AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill,
                SelectionMode = DataGridViewSelectionMode.FullRowSelect,
                DataSource = _vm.Incidents,
            };
            _gridIncidents.Columns.Clear();
            AddCol(nameof(SecurityIncident.Timestamp), "Время", 150);
            AddCol(nameof(SecurityIncident.EventType), "Событие", 130);
            AddCol(nameof(SecurityIncident.Severity), "Серьёзность", 100);
            AddCol(nameof(SecurityIncident.VidPid), "VID/PID", 140);
            AddCol(nameof(SecurityIncident.SerialNumber), "SN", 120);
            AddCol(nameof(SecurityIncident.DriveLetters), "Том", 80);
            AddCol(nameof(SecurityIncident.ActionApplied), "Мера", 120);
            AddCol(nameof(SecurityIncident.FindingsCount), "Находок", 70);
            AddCol(nameof(SecurityIncident.DeliveryStatus), "Доставка", 90);

            _gridIncidents.SelectionChanged += (_, _) => ShowDetails();

            _details = new TextBox
            {
                Dock = DockStyle.Fill,
                Multiline = true,
                ReadOnly = true,
                ScrollBars = ScrollBars.Vertical,
                Font = new Font("Consolas", 9f),
                BackColor = Color.WhiteSmoke,
            };

            var btnRefresh = new Button { Text = "Обновить из NDJSON", Dock = DockStyle.Right };
            btnRefresh.Click += async (_, _) => await _vm.ReloadIncidentsAsync();
            var panel = new Panel { Dock = DockStyle.Bottom, Height = 34 };
            panel.Controls.Add(btnRefresh);

            _split.Panel1.Controls.Add(_gridIncidents);
            _split.Panel2.Controls.Add(_details);
            _split.Panel2.Controls.Add(panel);

            Controls.Add(_split);

            _ = _vm.ReloadIncidentsAsync();
        }

        private void AddCol(string prop, string header, int width)
        {
            var idx = _gridIncidents.Columns.Add(prop, header);
            if (idx >= 0) _gridIncidents.Columns[idx].FillWeight = width;
        }

        private void ShowDetails()
        {
            if (_gridIncidents.CurrentRow?.DataBoundItem is not SecurityIncident inc)
            {
                _details.Text = string.Empty;
                return;
            }

            var sb = new System.Text.StringBuilder();
            sb.AppendLine($"Инцидент: {inc.Id}");
            sb.AppendLine($"Тип: {inc.EventType}   Серьёзность: {inc.Severity}   Доставка: {inc.DeliveryStatus}");
            sb.AppendLine($"Станция: {inc.HostName}\\{inc.UserName}   Время: {inc.Timestamp.ToLocalTime():yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine($"Устройство: {inc.ProductName} ({inc.Manufacturer}), {inc.VidPid}, SN={inc.SerialNumber}, том {inc.DriveLetters}");
            sb.AppendLine($"Описание: {inc.Description}");
            if (inc.Findings.Count > 0)
            {
                sb.AppendLine();
                sb.AppendLine("—— Находки ——");
                foreach (var f in inc.Findings)
                    sb.AppendLine($"  [{f.Severity}] {f.Category}: {f.RuleName} → \"{f.MaskedMatch}\" в {f.RelativePath}:{f.LineNumber}");
            }
            if (inc.QuarantinedFiles.Count > 0)
            {
                sb.AppendLine();
                sb.AppendLine("—— Карантин ——");
                foreach (var q in inc.QuarantinedFiles)
                    sb.AppendLine($"  {q.OriginalFullPath} → {q.QuarantinedFilePath} (SHA256:{q.Sha256Original[..16]}…, {q.SizeBytes} Б)");
            }
            _details.Text = sb.ToString();
        }
    }
}
