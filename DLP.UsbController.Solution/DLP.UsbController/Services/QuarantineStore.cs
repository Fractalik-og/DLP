using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace DLP.UsbController.Services
{
    /// <summary>Метаданные изолированного файла (хранятся рядом с содержимым в карантине).</summary>
    public sealed class QuarantineEntry
    {
        [JsonPropertyName("id")]
        public string Id { get; set; } = "";

        /// <summary>Исходное имя файла (например report.txt).</summary>
        [JsonPropertyName("original_name")]
        public string OriginalName { get; set; } = "";

        /// <summary>Полный путь на USB-носителе до изъятия.</summary>
        [JsonPropertyName("original_path")]
        public string OriginalPath { get; set; } = "";

        /// <summary>Относительный путь файла внутри карантина (.dat).</summary>
        [JsonPropertyName("stored_file")]
        public string StoredFile { get; set; } = "";

        [JsonPropertyName("size_bytes")]
        public long SizeBytes { get; set; }

        [JsonPropertyName("sha256")]
        public string Sha256 { get; set; } = "";

        [JsonPropertyName("policy")]
        public string Policy { get; set; } = "";

        [JsonPropertyName("categories")]
        public List<string> Categories { get; set; } = [];

        [JsonPropertyName("markers")]
        public List<string> Markers { get; set; } = [];

        [JsonPropertyName("incident_id")]
        public string IncidentId { get; set; } = "";

        [JsonPropertyName("device")]
        public string Device { get; set; } = "";

        [JsonPropertyName("serial")]
        public string? Serial { get; set; }

        [JsonPropertyName("drive")]
        public string? Drive { get; set; }

        [JsonPropertyName("quarantined_at_utc")]
        public DateTime QuarantinedAtUtc { get; set; } = DateTime.UtcNow;

        [JsonIgnore]
        public string SizeText => FormatSize(SizeBytes);

        [JsonIgnore]
        public DateTime QuarantinedLocal => QuarantinedAtUtc.ToLocalTime();

        public static string FormatSize(long bytes) => bytes switch
        {
            >= 1L << 30 => $"{bytes / 1024.0 / 1024 / 1024:0.##} ГБ",
            >= 1L << 20 => $"{bytes / 1024.0 / 1024:0.##} МБ",
            >= 1024 => $"{bytes / 1024.0:0.#} КБ",
            _ => $"{bytes} Б",
        };
    }

    /// <summary>
    /// Хранилище карантина: каталог protected dir, где каждому изъятому файлу
    /// соответствуют два объекта:
    ///   Q-000001.dat  — оригинальное содержимое;
    ///   Q-000001.json — метаданные (исходный путь, SHA-256, политика, инцидент).
    /// Каталог создаётся с ограничением доступа для обычных пользователей (Windows ACL).
    /// </summary>
    public sealed class QuarantineStore
    {
        private static readonly JsonSerializerOptions MetaOpts = new()
        {
            WriteIndented = true,
            Converters = { new JsonStringEnumConverter() },
        };

        private readonly object _sync = new();
        private readonly Dictionary<string, string> _pathToId = new(StringComparer.OrdinalIgnoreCase);
        private int _counter;

        public string Directory { get; }

        public QuarantineStore(string directory)
        {
            Directory = Path.GetFullPath(directory);
            Directory.CreateDirectory(Directory);
            TryRestrictAccess();
            LoadExistingIds();
        }

        /// <summary>Все записи карантина, свежие сверху.</summary>
        public IReadOnlyList<QuarantineEntry> GetEntries()
        {
            var list = new List<QuarantineEntry>();
            foreach (var json in SafeEnumerate("*.json"))
            {
                try
                {
                    var e = JsonSerializer.Deserialize<QuarantineEntry>(File.ReadAllText(json), MetaOpts);
                    if (e is not null && !string.IsNullOrEmpty(e.Id)) list.Add(e);
                }
                catch (JsonException) { /* повреждённая метадата — пропускаем */ }
                catch (IOException) { }
            }
            return list.OrderByDescending(e => e.QuarantinedAtUtc).ToList();
        }

        public QuarantineEntry? FindById(string id) =>
            GetEntries().FirstOrDefault(e => string.Equals(e.Id, id, StringComparison.OrdinalIgnoreCase));

        /// <summary>Проверить, что файл уже изъят (защита от повторного скана одной «флешки»).</summary>
        public bool IsQuarantined(string originalPath)
        {
            lock (_sync)
                return _pathToId.ContainsKey(Path.GetFullPath(originalPath));
        }

        /// <summary>Зарегистрировать ранее изъятый файл (используется модулем принуждения).</summary>
        public QuarantineEntry Register(
            string originalPath, string storedDataFile, byte[] sha256, long sizeBytes,
            string policy, IEnumerable<string> categories, IEnumerable<string> markers,
            string incidentId, string device, string? serial, string? drive)
        {
            string id;
            string fullOriginal;
            lock (_sync)
            {
                fullOriginal = Path.GetFullPath(originalPath);
                if (!_pathToId.TryGetValue(fullOriginal, out id!))
                {
                    _counter++;
                    id = $"Q-{_counter:D6}";
                    _pathToId[fullOriginal] = id;
                }
            }

            var entry = new QuarantineEntry
            {
                Id = id,
                OriginalName = Path.GetFileName(fullOriginal),
                OriginalPath = fullOriginal,
                StoredFile = Path.GetRelativePath(Directory, storedDataFile),
                SizeBytes = sizeBytes,
                Sha256 = Convert.ToHexString(sha256),
                Policy = policy,
                Categories = categories.Distinct().ToList(),
                Markers = markers.Take(20).Distinct().ToList(),
                IncidentId = incidentId,
                Device = device,
                Serial = serial,
                Drive = drive,
                QuarantinedAtUtc = DateTime.UtcNow,
            };

            File.WriteAllText(Path.Combine(Directory, id + ".json"), JsonSerializer.Serialize(entry, MetaOpts));
            return entry;
        }

        /// <summary>Следующий идентификатор инцидента вида INC-гггг-мм-дд-NNNN.</summary>
        public string NextIncidentId()
        {
            lock (_sync)
            {
                _incCounter++;
                return $"INC-{DateTime.Now:yyyy-MM-dd}-{_incCounter:D4}";
            }
        }

        private int _incCounter;

        /// <summary>Удалить запись из карантина (файл + метаданные).</summary>
        public bool Remove(string id)
        {
            var entry = FindById(id);
            if (entry is null) return false;
            TryDelete(Path.Combine(Directory, id + ".json"));
            TryDelete(Path.GetFullPath(Path.Combine(Directory, entry.StoredFile)));
            lock (_sync) _pathToId.Remove(entry.OriginalPath);
            return true;
        }

        private void LoadExistingIds()
        {
            foreach (var e in GetEntries())
            {
                lock (_sync) _pathToId[e.OriginalPath] = e.Id;
                if (e.Id.StartsWith("Q-", StringComparison.Ordinal) &&
                    int.TryParse(e.Id.AsSpan(2), out var n) && n > _counter)
                    _counter = n;
            }
        }

        private IEnumerable<string> SafeEnumerate(string pattern)
        {
            try { return Directory.EnumerateFiles(this.Directory, pattern).ToList(); }
            catch (IOException) { return []; }
            catch (UnauthorizedAccessException) { return []; }
        }

        private static void TryDelete(string path)
        {
            try { if (File.Exists(path)) File.Delete(path); }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }

        /// <summary>Ограничение доступа к каталогу: только администраторы и SYSTEM (Windows).</summary>
        private void TryRestrictAccess()
        {
            if (!OperatingSystem.IsWindows()) return;
            try
            {
                var dirInfo = new DirectoryInfo(Directory);
                var sec = dirInfo.GetAccessControl();
                sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
                sec.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                    @"NT AUTHORITY\SYSTEM",
                    System.Security.AccessControl.FileSystemRights.FullControl,
                    System.Security.AccessControl.InheritanceFlags.ContainerInherit |
                    System.Security.AccessControl.InheritanceFlags.ObjectInherit,
                    System.Security.AccessControl.PropagationFlags.None,
                    System.Security.AccessControl.AccessControlType.Allow));
                sec.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                    @"BUILTIN\Administrators",
                    System.Security.AccessControl.FileSystemRights.FullControl,
                    System.Security.AccessControl.InheritanceFlags.ContainerInherit |
                    System.Security.AccessControl.InheritanceFlags.ObjectInherit,
                    System.Security.AccessControl.PropagationFlags.None,
                    System.Security.AccessControl.AccessControlType.Allow));
                dirInfo.SetAccessControl(sec);
            }
            catch (Exception)
            {
                // Нет прав на смену ACL (обычный запуск) — карантин работает в общем каталоге,
                // ограничение доступа демонстрируется только при запуске от администратора.
            }
        }
    }
}
