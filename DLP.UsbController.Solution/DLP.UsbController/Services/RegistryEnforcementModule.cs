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
        private readonly Dictionary<string, DeviceWritePolicyState> _states = new(StringComparer.OrdinalIgnoreCase);
        private bool _disposed;

        public string StubTemplate { get; set; } =
            "██████████████████████████████████████████████████████████████\r\n" +
            "  ВНИМАНИЕ! Файл изъят агентом DLP-системы.\r\n" +
            "  Основание: политика информационной безопасности №{policy}.\r\n" +
            "  Причина: в содержимом обнаружена конфиденциальная информация\r\n" +
            "           ({categories}).\r\n" +
            "  Оригинал помещён в карантин: {quarantinePath}\r\n" +
            "  Инцидент: {incidentId}. Для возврата обратитесь к администратору ИБ.\r\n" +
            "██████████████████████████████████████████████████████████████\r\n";

        public RegistryEnforcementModule(DlpPolicyConfig policy) => _policy = policy;

        public Task<bool> SetReadOnlyAsync(UsbDeviceId deviceId, string? serialNumber, CancellationToken cancellationToken = default)
        {
            string key = StateKey(deviceId, serialNumber);
            if (!_states.TryGetValue(key, out var state))
                state = _states[key] = new DeviceWritePolicyState { DeviceId = deviceId, SerialNumber = serialNumber };

            bool ok = TryModifyRegistry(value =>
            {
                state.OriginalWriteProtectValue ??= value;      // запоминаем исходное значение один раз
                return 1;                                       // WriteProtect = 1 → только чтение
            });

            state.IsReadOnlyNow = ok;
            state.AppliedAtUtc = DateTime.UtcNow;
            return Task.FromResult(ok);
        }

        public Task<bool> RestoreReadWriteAsync(UsbDeviceId deviceId, string? serialNumber, CancellationToken cancellationToken = default)
        {
            string key = StateKey(deviceId, serialNumber);
            if (!_states.TryGetValue(key, out var state)) return Task.FromResult(false);

            int? original = state.OriginalWriteProtectValue;
            bool ok = TryModifyRegistry(_ => original ?? 0);

            state.IsReadOnlyNow = false;
            state.RestoredAtUtc = DateTime.UtcNow;
            return Task.FromResult(ok);
        }

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

                var fi = new FileInfo(path);
                string qName = $"{Sanitize(fi.Name)}.{Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(path))[..4])}.qdata";
                string qPath = Path.Combine(sessionDir, qName);

                // 1. Копируем оригинал в карантин, считаем SHA-256.
                string sha;
                await using (var src = fi.OpenRead())
                await using (var dst = File.Create(qPath))
                {
                    using var sha256 = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                    var hash = await sha256.ComputeHashAsync(src, cancellationToken).ConfigureAwait(false);
                    sha = Convert.ToHexString(hash);
                    src.Position = 0;
                    await src.CopyToAsync(dst, cancellationToken).ConfigureAwait(false);
                }
                // Проверяем подпись карантина отдельным хешем пути+данных (упрощённо — метаданные рядом).
                await File.WriteAllTextAsync(qPath + ".meta",
                    $"path={path}\r\nsha256={sha}\r\nsize={fi.Length}\r\nutc={DateTime.UtcNow:o}\r\n",
                    cancellationToken).ConfigureAwait(false);

                // 2. Подмена оригинала файлом-заглушкой с уведомлением.
                findingsByFile.TryGetValue(path, out var findings);
                string stubText = BuildStub(path, qPath, findings ?? []);
                TryRemoveReadOnly(path);
                await File.WriteAllTextAsync(path, stubText, Encoding.UTF8, cancellationToken).ConfigureAwait(false);

                records.Add(new QuarantineRecord
                {
                    OriginalFullPath = path,
                    QuarantinedFilePath = qPath,
                    StubFilePath = path,
                    Sha256Original = sha,
                    SizeBytes = fi.Length,
                    Findings = findings ?? [],
                });
            }

            return records;
        }

        private string BuildStub(string originalPath, string quarantinePath, IReadOnlyList<ContentFinding> findings)
        {
            var cats = findings.Select(f => f.Category).Distinct().OrderBy(x => x);
            return StubTemplate
                .Replace("{policy}", "USB-DLP-01")
                .Replace("{categories}", string.Join(", ", cats.Any() ? cats : new[] { "Keyword" }))
                .Replace("{quarantinePath}", quarantinePath)
                .Replace("{incidentId}", Guid.NewGuid().ToString("N"))
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
