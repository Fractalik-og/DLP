using System.Text.Json;
using DLP.UsbController.Models;

namespace DLP.UsbController.Services
{
    /// <summary>Запись реестра зарегистрированных (доверенных) флешек.</summary>
    public sealed class RegisteredDevice
    {
        public string Serial { get; set; } = "";
        public string VidPid { get; set; } = "";
        public string Label { get; set; } = "";
        public DateTime RegisteredAtUtc { get; set; } = DateTime.UtcNow;

        /// <summary>Дата регистрации для таблицы UI.</summary>
        public string RegisteredLocalText => RegisteredAtUtc.ToLocalTime().ToString("dd.MM.yyyy HH:mm");

        /// <summary>Ключ сопоставления: серийник либо VID/PID.</summary>
        public string MatchKey => !string.IsNullOrWhiteSpace(Serial) ? $"SN:{Serial}" : $"ID:{VidPid}";
    }

    /// <summary>Файл JSON-схемы: {"devices":[...]}.</summary>
    internal sealed class RegistryFileDto
    {
        public List<RegisteredDevice> Devices { get; set; } = [];
    }

    /// <summary>
    /// Реестр носителей, имеющих право доступа (аналог белого списка).
    /// Хранится в JSON-файле рядом с политикой (registered_devices.json),
    /// синхронизируется с DlpPolicyConfig.WhitelistedSerialNumbers / WhitelistedDeviceIds,
    /// поэтому агент сразу начинает пропускать зарегистрированную флешку без ограничений.
    /// </summary>
    public sealed class DeviceRegistry
    {
        private static readonly JsonSerializerOptions Opts = new() { WriteIndented = true };

        private readonly string _filePath;
        private readonly DlpPolicyConfig _policy;
        private readonly object _sync = new();
        private List<RegisteredDevice> _items;

        public event Action? Changed;

        public DeviceRegistry(string filePath, DlpPolicyConfig policy)
        {
            _filePath = filePath;
            _policy = policy;
            _items = Load(filePath);
            ApplyToPolicy();
        }

        public IReadOnlyList<RegisteredDevice> Items
        {
            get { lock (_sync) return _items.ToList(); }
        }

        public bool IsRegistered(UsbDeviceId id, string? serial) =>
            _policy.IsWhitelisted(id, serial);

        /// <summary>Зарегистрировать устройство по серийному номеру (или VID/PID, если SN нет).</summary>
        public RegisteredDevice Register(UsbDeviceId id, string? serial, string label = "")
        {
            var dev = new RegisteredDevice
            {
                Serial = serial?.Trim() ?? "",
                VidPid = id.ToString(),
                Label = label,
            };
            lock (_sync)
            {
                if (!_items.Any(d => d.MatchKey == dev.MatchKey))
                    _items.Add(dev);
                Save();
            }
            ApplyToPolicy();
            Changed?.Invoke();
            return dev;
        }

        public bool Unregister(string matchKey)
        {
            bool removed;
            lock (_sync)
            {
                removed = _items.RemoveAll(d => d.MatchKey.Equals(matchKey, StringComparison.OrdinalIgnoreCase)) > 0;
                if (removed) Save();
            }
            if (removed)
            {
                ApplyToPolicy();
                Changed?.Invoke();
            }
            return removed;
        }

        /// <summary>Пересобрать списки белого списка политики из реестра.</summary>
        private void ApplyToPolicy()
        {
            lock (_sync)
            {
                _policy.WhitelistedSerialNumbers = _items
                    .Where(d => !string.IsNullOrWhiteSpace(d.Serial))
                    .Select(d => d.Serial).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
                _policy.WhitelistedDeviceIds = _items
                    .Select(d => d.VidPid)
                    .Where(s => !string.IsNullOrWhiteSpace(s))
                    .Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
            }
        }

        private static List<RegisteredDevice> Load(string path)
        {
            try
            {
                if (File.Exists(path))
                    return JsonSerializer.Deserialize<RegistryFileDto>(File.ReadAllText(path), Opts)?.Devices ?? [];
            }
            catch (JsonException) { /* повреждённый файл — начинаем пусто */ }
            catch (IOException) { }
            return [];
        }

        private void Save()
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(_filePath)!);
                File.WriteAllText(_filePath, JsonSerializer.Serialize(new RegistryFileDto { Devices = _items }, Opts));
            }
            catch (IOException) { /* best effort: без прав на запись каталога */ }
        }
    }
}
