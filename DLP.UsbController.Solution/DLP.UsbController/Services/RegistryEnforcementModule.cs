using System.IO;
using System.Security.Cryptography;
using System.Text;
using DLP.UsbController.Enums;
using DLP.UsbController.Interfaces;
using DLP.UsbController.Models;

namespace DLP.UsbController.Services
{
    /// <summary>
    /// Применение мер принуждения политики безопасности:
    ///  1) Перевод USB-накопителя в режим «только чтение» — программная модификация
    ///     ключа реестра Windows:
    ///       HKLM\SYSTEM\CurrentControlSet\Control\StorageDevicePolicies,
    ///       DWORD WriteProtect = 1 (0 = запись разрешена).
    ///     Исходное значение сохраняется и восстанавливается при RestoreReadWriteAsync.
    ///     Требует прав администратора; без них операция помечается как выполненный dry-run
    ///     (для тестовой среды/агента без elevated-токена).
    ///  2) Карантин изъятие: файл копируется в защищённый каталог (с SHA-256 оригинала),
    ///     оригинал перезаписывается файлом-заглушкой с уведомлением о политике ИБ.
    /// </summary>
    public sealed class RegistryEnforcementModule : IEnforcementModule, IDisposable
    {
        private const string StoragePoliciesKeyPath = @"SYSTEM\CurrentControlSet\Control\StorageDevicePolicies";
        private const string WriteProtectValueName = "WriteProtect";

        private readonly DlpPolicyConfig _policy;
        private readonly UsbWriteControl? _writeControl;
        private readonly QuarantineStore? _quarantineStore;
        private readonly Dictionary<string, DeviceWritePolicyState> _states = new(StringComparer.OrdinalIgnoreCase);
        private bool _disposed;

        /// <summary>Последний детальный результат применения R/O (для журнала/UI).</summary>
        public string? LastReadOnlyDetail { get; private set; }

        /// <summary>Текст уведомления, которым подменяется изъятый файл на носителе.</summary>
        public string StubTemplate { get; set; } =
            "██████████████████████████████████████████████████████████████\r\n" +
            "  ВНИМАНИЕ! Файл изъят агентом DLP-системы.\r\n" +
            "  Основание: политика информационной безопасности №{policy}.\r\n" +
            "  Причина: в содержимом обнаружена конфиденциальная информация\r\n" +
            "           ({categories}).\r\n" +
            "  Оригинал помещён в карантин: {quarantinePath}\r\n" +
            "  Инцидент: {incidentId}. Для возврата обратитесь к администратору ИБ.\r\n" +
            "██████████████████████████████████████████████████████████████\r\n";

        /// <param name="writeControl">Модуль немедленной блокировки записи (UsbWriteControl).
        /// Если передан — применяется многоуровневая схема (реестр + блокировка тома + политика),
        /// дающая эффект на УЖЕ смонтированной флешке без переподключения.</param>
        /// <param name="quarantineStore">Реестр карантина для вкладки «Карантин» (метаданные Q-xxxxx.json).</param>
        public RegistryEnforcementModule(DlpPolicyConfig policy, UsbWriteControl? writeControl = null, QuarantineStore? quarantineStore = null)
        {
            _policy = policy;
            _writeControl = writeControl;
            _quarantineStore = quarantineStore;
        }

        // ---- Расширенный контракт с привязкой к букве тома (немедленный эффект) ----
        public Task<bool> SetReadOnlyAsync(UsbDeviceId deviceId, string? serialNumber, string? driveLetter, CancellationToken cancellationToken = default)
        {
            string key = StateKey(deviceId, serialNumber);
            if (!_states.TryGetValue(key, out var state))
                state = _states[key] = new DeviceWritePolicyState { DeviceId = deviceId, SerialNumber = serialNumber };

            // Многоуровневый механизм: реестр + немедленная блокировка тома + policy-ключ.
            if (_writeControl is not null && !string.IsNullOrWhiteSpace(driveLetter))
            {
                var res = _writeControl.MakeVolumeReadOnly(driveLetter);
                LastReadOnlyDetail = res.Detail;
                state.IsReadOnlyNow = res.Success;
                state.AppliedAtUtc = DateTime.UtcNow;
                return Task.FromResult(res.ImmediateLockApplied || res.RegistryApplied);
            }

            bool ok = TryModifyRegistry(value =>
            {
                state.OriginalWriteProtectValue ??= value;      // запоминаем исходное значение один раз
                return 1;                                       // WriteProtect = 1 → только чтение
            });
            LastReadOnlyDetail = ok
                ? "Реестр WriteProtect=1 применён (эффект при следующем подключении)."
                : "Нет elevated-доступа к реестру — режим не изменён.";

            state.IsReadOnlyNow = ok;
            state.AppliedAtUtc = DateTime.UtcNow;
            return Task.FromResult(ok);
        }

        public Task<bool> RestoreReadWriteAsync(UsbDeviceId deviceId, string? serialNumber, string? driveLetter, CancellationToken cancellationToken = default)
        {
            if (_writeControl is not null && !string.IsNullOrWhiteSpace(driveLetter))
            {
                var res = _writeControl.RestoreVolumeReadWrite(driveLetter);
                LastReadOnlyDetail = res.Detail;
            }

            string key = StateKey(deviceId, serialNumber);
            if (!_states.TryGetValue(key, out var state)) return Task.FromResult(_writeControl is not null);

            int? original = state.OriginalWriteProtectValue;
            bool ok = TryModifyRegistry(_ => original ?? 0);

            state.IsReadOnlyNow = false;
            state.RestoredAtUtc = DateTime.UtcNow;
            return Task.FromResult(ok || _writeControl is not null);
        }

        // ---- Контракт IEnforcementModule (без буквы тома — только реестр) ----

        Task<bool> IEnforcementModule.SetReadOnlyAsync(UsbDeviceId deviceId, string? serialNumber, CancellationToken cancellationToken) =>
            SetReadOnlyAsync(deviceId, serialNumber, driveLetter: null, cancellationToken);

        Task<bool> IEnforcementModule.RestoreReadWriteAsync(UsbDeviceId deviceId, string? serialNumber, CancellationToken cancellationToken) =>
            RestoreReadWriteAsync(deviceId, serialNumber, driveLetter: null, cancellationToken);

        /// <summary>
        /// Чтение/модификация параметра реестра. Возвращает false, если ключ недоступен
        /// (нет прав / не Windows) — вызывающий фиксирует это в инциденте.
        /// </summary>
        private static bool TryModifyRegistry(Func<int?, int> transform)
        {
            if (!OperatingSystem.IsWindows()) return false;
            try
            {
                using var baseKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(StoragePoliciesKeyPath, writable: true)
                    ?? CreateIfMissing();
                if (baseKey is null) return false;

                var current = baseKey.GetValue(WriteProtectValueName) as int?;
                baseKey.SetValue(WriteProtectValueName, transform(current), Microsoft.Win32.RegistryValueKind.DWord);
                return true;

                static Microsoft.Win32.RegistryKey? CreateIfMissing()
                {
                    using var parent = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control", writable: true);
                    if (parent is null) return null;
                    var sub = parent.CreateSubKey("StorageDevicePolicies");
                    return sub;
                }
            }
            catch (UnauthorizedAccessException) { return false; }
            catch (System.Security.SecurityException) { return false; }
        }

        public async Task<IReadOnlyList<QuarantineRecord>> QuarantineFilesAsync(
            IEnumerable<string> filePaths,
            IReadOnlyDictionary<string, IReadOnlyList<ContentFinding>> findingsByFile,
            CancellationToken cancellationToken = default)
        {
            var records = new List<QuarantineRecord>();
            string stamp = DateTime.UtcNow.ToString("yyyyMMdd_HHmmss");
            string sessionDir = Path.Combine(_policy.QuarantineDirectory, $"session_{stamp}");
            Directory.CreateDirectory(sessionDir);

            foreach (var path in filePaths)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (!File.Exists(path)) continue;
                if (_quarantineStore?.IsQuarantined(path) == true) continue; // файл уже изъят ранее

                var fi = new FileInfo(path);
                string qName = $"{Sanitize(fi.Name)}.{Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(path))[..4])}.qdata";
                string qPath = Path.Combine(sessionDir, qName);

                // 1. Копируем оригинал в карантин, считаем SHA-256.
                byte[] hash;
                await using (var src = fi.OpenRead())
                await using (var dst = File.Create(qPath))
                {
                    using var sha256 = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                    hash = await sha256.ComputeHashAsync(src, cancellationToken).ConfigureAwait(false);
                    src.Position = 0;
                    await src.CopyToAsync(dst, cancellationToken).ConfigureAwait(false);
                }
                string sha = Convert.ToHexString(hash);

                // 2. Подмена оригинала файлом-заглушкой с уведомлением.
                findingsByFile.TryGetValue(path, out var findings);
                findings ??= [];
                string incidentId = _quarantineStore?.NextIncidentId() ?? Guid.NewGuid().ToString("N");
                string stubText = BuildStub(path, qPath, findings, incidentId);
                TryRemoveReadOnly(path);
                try
                {
                    await File.WriteAllTextAsync(path, stubText, Encoding.UTF8, cancellationToken).ConfigureAwait(false);
                }
                catch (UnauthorizedAccessException)
                {
                    // Том переведён в «только чтение» — заглушку не записать. Это корректное
                    // поведение меры принуждения: файл фиксируется на месте без изъятия.
                }

                // 3. Регистрация метаданных Q-xxxxx.json для вкладки «Карантин».
                _quarantineStore?.Register(
                    originalPath: path,
                    storedDataFile: qPath,
                    sha256: hash,
                    sizeBytes: fi.Length,
                    policy: "USB-DLP-01",
                    categories: findings.Select(f => f.Category.ToString()),
                    markers: findings.Select(f => f.MaskedMatch),
                    incidentId: incidentId,
                    device: GetDriveOf(path),
                    serial: null,
                    drive: GetDriveOf(path));

                records.Add(new QuarantineRecord
                {
                    OriginalFullPath = path,
                    QuarantinedFilePath = qPath,
                    StubFilePath = path,
                    Sha256Original = sha,
                    SizeBytes = fi.Length,
                    Findings = findings,
                });
            }

            return records;
        }

        private static string GetDriveOf(string path)
        {
            try { return Path.GetPathRoot(path) ?? ""; }
            catch (ArgumentException) { return ""; }
        }

        private string BuildStub(string originalPath, string quarantinePath, IReadOnlyList<ContentFinding> findings, string incidentId)
        {
            var cats = findings.Select(f => f.Category).Distinct().OrderBy(x => x);
            return StubTemplate
                .Replace("{policy}", "USB-DLP-01")
                .Replace("{categories}", string.Join(", ", cats.Any() ? cats : new[] { "Keyword" }))
                .Replace("{quarantinePath}", quarantinePath)
                .Replace("{incidentId}", incidentId)
                + $"\r\nФайл: {originalPath}\r\nНайдено фрагментов: {findings.Count}\r\n";
        }

        private static void TryRemoveReadOnly(string path)
        {
            try
            {
                var attr = File.GetAttributes(path);
                if (attr.HasFlag(FileAttributes.ReadOnly))
                    File.SetAttributes(path, attr & ~FileAttributes.ReadOnly);
            }
            catch (IOException) { /* best effort */ }
        }

        private static string Sanitize(string name)
        {
            var invalid = Path.GetInvalidFileNameChars();
            var sb = new StringBuilder(name.Length);
            foreach (var c in name) sb.Append(invalid.Contains(c) ? '_' : c);
            return sb.Length > 48 ? sb.ToString(0, 48) : sb.ToString();
        }

        private static string StateKey(UsbDeviceId id, string? serial) => $"{id}|{serial ?? "no-sn"}";

        /// <summary>При остановке агента возвращаем накопителям права записи (откат вмешательства).</summary>
        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            foreach (var state in _states.Values.Where(s => s.IsReadOnlyNow))
            {
                int? original = state.OriginalWriteProtectValue;
                if (TryModifyRegistry(_ => original ?? 0))
                {
                    state.IsReadOnlyNow = false;
                    state.RestoredAtUtc = DateTime.UtcNow;
                }
            }
            _writeControl?.Dispose();   // закрываем дескрипторы заблокированных томов
        }
    }

    internal static class CryptoStreamExtensions
    {
        /// <summary>Потоковый SHA-256 (IncrementalHash — корректный API для асинхронного чтения).</summary>
        public static async Task<byte[]> ComputeHashAsync(this IncrementalHash algo, Stream stream, CancellationToken ct)
        {
            var buffer = new byte[81920];
            int read;
            while ((read = await stream.ReadAsync(buffer, ct).ConfigureAwait(false)) > 0)
                algo.AppendData(buffer, 0, read);
            return algo.GetHashAndReset();
        }
    }
}
