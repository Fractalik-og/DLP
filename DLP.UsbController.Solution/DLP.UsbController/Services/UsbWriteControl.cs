using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using DLP.UsbController.Enums;
using Microsoft.Win32;

namespace DLP.UsbController.Services
{
    /// <summary>
    /// Надёжный модуль разграничения прав на съёмные носители.
    ///
    /// ИСПРАВЛЕНИЕ ПРОШЛОЙ ВЕРСИИ: ранее использовался единственный системный флаг
    /// HKLM\SYSTEM\CurrentControlSet\Control\StorageDevicePolicies\WriteProtect.
    /// Windows применяет его ТОЛЬКО при следующем подключении устройства, поэтому
    /// флешка, уже смонтированная на момент запуска агента (даже с правами админа),
    /// режим «только чтение» не меняла. Теперь применяются три механизма одновременно:
    ///
    ///  1) Реестр (на будущее подключение): StorageDevicePolicies\WriteProtect=1 —
    ///     стандартный способ перевода USB-накопителей в R/O на уровне фильтра
    ///     накопителя; исходное значение сохраняется и восстанавливается.
    ///  2) Немедленная блокировка записи для УЖЕ СМОНТИРОВАННОГО тома: том открывается
    ///     через CreateFile("\\.\E:") с доступом GENERIC_READ и share mode READ ONLY.
    ///     Пока агент удерживает дескриптор, проводник и приложения не могут получить
    ///     запись на уровень тома, а сам том нельзя отмонтировать/извлечь — эффект
    ///     наступает сразу, без переподключения. Снятие блокировки = закрытие
    ///     дескриптора. Требует elevated-токена.
    ///  3) Policy-ключ RemovableStorageDevices\{класс USB Mass Storage}\Deny_Write=1
    ///     (аналог групповой политики «Запретить запись на съёмные накопители»).
    ///
    /// Факт применения каждого уровня возвращается в <see cref="ReadOnlyApplyResult"/>
    /// и попадает в инцидент/журнал, чтобы оператор видел, что реально сработало.
    /// </summary>
    public sealed class UsbWriteControl : IDisposable
    {
        private const string StoragePoliciesKey = @"SYSTEM\CurrentControlSet\Control\StorageDevicePolicies";
        private const string WriteProtectValue = "WriteProtect";
        private const string PoliciesKey = @"SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630d-b6bf-4ff9-927b-68b6e8e33616}"; // класс USB Mass Storage
        private const string DenyWriteValue = "Deny_Write";

        private readonly object _sync = new();
        private readonly Dictionary<string, VolumeLockHandle> _lockedVolumes = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, int?> _originalWriteProtect = new(StringComparer.OrdinalIgnoreCase);

        /// <summary>Результат применения режима «только чтение» к тому.</summary>
        public sealed record ReadOnlyApplyResult(bool RegistryApplied, bool ImmediateLockApplied, bool PolicyApplied, string Detail)
        {
            public bool Success => RegistryApplied || ImmediateLockApplied || PolicyApplied;
        }

        // ---------------- Win32: немедленная блокировка записи ----------------

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern SafeFileHandle CreateFileW(
            string lpFileName, uint dwDesiredAccess, uint dwShareMode,
            IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

        private const uint GENERIC_READ = 0x80000000;
        private const uint FILE_SHARE_READ = 0x00000001;
        private const uint OPEN_EXISTING = 3;

        /// <summary>Дескриптор тома, открытый только на чтение: пока он удерживается,
        /// другие процессы не могут получить эксклюзивный доступ для записи на уровне файловой системы тома.</summary>
        private sealed class VolumeLockHandle : IDisposable
        {
            public required SafeFileHandle Handle { get; init; }
            public required string DriveLetter { get; init; }
            public DateTime LockedAtUtc { get; } = DateTime.UtcNow;
            public void Dispose() => Handle.Dispose();
        }

        /// <summary>
        /// Перевести том в режим «только чтение»: реестр + немедленная блокировка записи + политика.
        /// Вызывается из агентa при обнаружении носителя и из UI по кнопке.
        /// </summary>
        public ReadOnlyApplyResult MakeVolumeReadOnly(string driveLetter)
        {
            driveLetter = Normalize(driveLetter);
            bool elevated = IsElevated();

            // Уровень 1+3: реестр (системный флаг WriteProtect и запрет записи политикой).
            bool regOk = false, polOk = false;
            if (elevated)
            {
                try
                {
                    using (var key = OpenOrCreate(HKLM, StoragePoliciesKey))
                    {
                        if (key is not null)
                        {
                            lock (_sync)
                                _originalWriteProtect.TryAdd("*", key.GetValue(WriteProtectValue) as int?);
                            key.SetValue(WriteProtectValue, 1, RegistryValueKind.DWord);
                            regOk = true;
                        }
                    }
                    using (var pol = OpenOrCreate(HKLM, PoliciesKey))
                    {
                        if (pol is not null)
                        {
                            pol.SetValue(DenyWriteValue, 1, RegistryValueKind.DWord);
                            polOk = true;
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (System.Security.SecurityException) { }
            }

            // Уровень 2: немедленная блокировка записи уже смонтированного тома.
            bool locked = TryLockVolumeWrite(driveLetter, out string lockDetail);

            string detail =
                $"реестр WriteProtect=1: {(regOk ? "применён (эффект — при следующем подключении)" : elevated ? "не применён" : "пропущен (нужны права администратора)")}; " +
                $"политика Deny_Write: {(polOk ? "применена" : "не применена")}; " +
                $"немедленная блокировка записи тома: {(locked ? "выполнена" : lockDetail)}";

            return new ReadOnlyApplyResult(regOk, locked, polOk, detail);
        }

        /// <summary>Снять блокировку: закрыть дескрипторы тома и вернуть исходные значения реестра.</summary>
        public ReadOnlyApplyResult RestoreVolumeReadWrite(string driveLetter)
        {
            driveLetter = Normalize(driveLetter);
            UnlockVolumeWrite(driveLetter);

            bool regOk = false, polOk = false;
            if (IsElevated())
            {
                try
                {
                    int? original;
                    lock (_sync)
                    {
                        _originalWriteProtect.TryGetValue("*", out original);
                        _originalWriteProtect.Remove("*");
                    }
                    using (var key = OpenOrCreate(HKLM, StoragePoliciesKey))
                    {
                        if (key is not null)
                        {
                            if (original is int v) key.SetValue(WriteProtectValue, v, RegistryValueKind.DWord);
                            else key.SetValue(WriteProtectValue, 0, RegistryValueKind.DWord);
                            regOk = true;
                        }
                    }
                    using (var pol = OpenOrCreate(HKLM, PoliciesKey))
                    {
                        if (pol is not null)
                        {
                            pol.SetValue(DenyWriteValue, 0, RegistryValueKind.DWord);
                            polOk = true;
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (System.Security.SecurityException) { }
            }
            return new ReadOnlyApplyResult(regOk, true, polOk, "Блокировка записи снята, реестр восстановлен.");
        }

        /// <summary>Немедленная блокировка записи на томе (удержание read-only дескриптора тома).</summary>
        private bool TryLockVolumeWrite(string driveLetter, out string detail)
        {
            detail = "";
            if (!OperatingSystem.IsWindows()) { detail = "не Windows"; return false; }
            lock (_sync)
            {
                if (_lockedVolumes.ContainsKey(driveLetter)) return true; // уже заблокирован
                try
                {
                    // Открываем том без прав записи и с share mode = READ ONLY:
                    // любые последующие попытки открытия тома на запись (FORMAT, изменение
                    // метаданных ФС, безопасное извлечение) будут отклонены ОС.
                    var h = CreateFileW($@"\.\\{driveLetter.TrimEnd('\\')}",
                        GENERIC_READ, FILE_SHARE_READ, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
                    if (h.IsInvalid)
                    {
                        detail = $"CreateFile тома не удался (код {Marshal.GetLastWin32Error()}, требуется elevated)";
                        return false;
                    }
                    _lockedVolumes[driveLetter] = new VolumeLockHandle { Handle = h, DriveLetter = driveLetter };
                    return true;
                }
                catch (Exception ex) { detail = ex.Message; return false; }
            }
        }

        private void UnlockVolumeWrite(string driveLetter)
        {
            lock (_sync)
            {
                if (_lockedVolumes.TryGetValue(driveLetter, out var h))
                {
                    h.Dispose();
                    _lockedVolumes.Remove(driveLetter);
                }
            }
        }

        public bool IsVolumeLocked(string driveLetter)
        {
            lock (_sync) return _lockedVolumes.ContainsKey(Normalize(driveLetter));
        }

        /// <summary>Признак повышенного токена процесса (администратор).</summary>
        public static bool IsElevated()
        {
            if (!OperatingSystem.IsWindows()) return false;
            try
            {
                using var id = System.Security.Principal.WindowsIdentity.GetCurrent();
                using var p = new System.Security.Principal.WindowsPrincipal(id);
                return p.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
            }
            catch { return false; }
        }

        private static RegistryKey? OpenOrCreate(RegistryKey root, string path)
        {
            var k = root.OpenSubKey(path, writable: true);
            if (k is not null) return k;
            // Создаём цепочку ключей (StorageDevicePolicies по умолчанию отсутствует).
            var parts = path.Split('\\');
            RegistryKey cur = root;
            foreach (var part in parts)
            {
                var next = cur.OpenSubKey(part, writable: true) ?? cur.CreateSubKey(part);
                if (next is null) return null;
                if (!ReferenceEquals(cur, root)) cur.Dispose();
                cur = next;
            }
            return cur;
        }

        private static RegistryKey HKLM => Registry.LocalMachine;

        private static string Normalize(string driveLetter)
        {
            driveLetter = driveLetter.Trim();
            if (driveLetter.Length == 2 && driveLetter[1] == ':') return driveLetter + "\\";
            if (driveLetter.Length == 1) return driveLetter + ":\\";
            return driveLetter;
        }

        public void Dispose()
        {
            List<string> letters;
            lock (_sync) letters = _lockedVolumes.Keys.ToList();
            foreach (var l in letters) UnlockVolumeWrite(l);
        }
    }
}
