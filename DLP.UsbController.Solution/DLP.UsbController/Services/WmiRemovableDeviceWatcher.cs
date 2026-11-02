using System.IO;
using System.Management;
using DLP.UsbController.Enums;
using DLP.UsbController.Interfaces;
using DLP.UsbController.Models;

namespace DLP.UsbController.Services
{
    /// <summary>
    /// Наблюдатель за съёмными USB-накопителями на базе подсистемы WMI (только Windows).
    ///
    /// Схема работы:
    ///  1) Подписка на потоковые запросы __InstanceCreationEvent / __InstanceDeletionEvent
    ///     по классу Win32_Volume с фильтром DriveType=2 (съёмный) — это даёт события
    ///     появления/исчезновения логических томов.
    ///  2) Параллельно опрашиваются Win32_DiskDrive (InterfaceMatch "USB") и цепочка
    ///     assoc-запросов DiskDrive → Partition → LogicalDisk, чтобы сопоставить
    ///     обнаруженный том с аппаратными признаками устройства (VID/PID, серийный номер).
    ///  3) Дедупликация по ключу "VID_PID;Serial" — повторное перемонтирование того же
    ///     тома не порождает ложного «подключения».
    /// </summary>
    public sealed class WmiRemovableDeviceWatcher : IRemovableDeviceWatcher
    {
        private ManagementEventWatcher? _arrivalWatcher;
        private ManagementEventWatcher? _removalWatcher;
        private readonly HashSet<string> _knownKeys = new(StringComparer.OrdinalIgnoreCase);
        private readonly object _sync = new();
        private CancellationTokenSource? _cts;
        private Task? _pollLoop;
        private bool _disposed;

        public event EventHandler<RemovableDeviceEventArgs>? DeviceArrived;
        public event EventHandler<RemovableDeviceEventArgs>? DeviceRemoved;

        public TimeSpan PollingInterval { get; set; } = TimeSpan.FromSeconds(3);

        public void Start()
        {
            if (!OperatingSystem.IsWindows())
                throw new PlatformNotSupportedException("WMI-наблюдатель доступен только в Windows.");
            ObjectDisposedException.ThrowIf(_disposed, this);

            _cts = new CancellationTokenSource();

            // Потоковые события WMI: том появился …
            _arrivalWatcher = NewWatcher(
                @"SELECT * FROM __InstanceCreationEvent WITHIN 2
                  WHERE TargetInstance ISA 'Win32_Volume' AND TargetInstance.DriveType = 2");
            _arrivalWatcher.EventArrived += (_, e) => OnVolumeChanged(e.NewEvent, isArrival: true);
            _arrivalWatcher.Start();

            // … и том исчез.
            _removalWatcher = NewWatcher(
                @"SELECT * FROM __InstanceDeletionEvent WITHIN 2
                  WHERE TargetInstance ISA 'Win32_Volume' AND TargetInstance.DriveType = 2");
            _removalWatcher.EventArrived += (_, e) => OnVolumeChanged(e.NewEvent, isArrival: false);
            _removalWatcher.Start();

            // Резервный поллинг: надёжнее потоковых событий при быстром insert/eject.
            var token = _cts.Token;
            _pollLoop = Task.Run(() => PollLoopAsync(token), token);
        }

        private static ManagementEventWatcher NewWatcher(string query) =>
            new(new ManagementScope(@"root\cimv2"), new WqlEventQuery(query));

        public async Task StopAsync()
        {
            try { _arrivalWatcher?.Stop(); _arrivalWatcher?.Dispose(); } catch { /* best effort */ }
            try { _removalWatcher?.Stop(); _removalWatcher?.Dispose(); } catch { /* best effort */ }
            _arrivalWatcher = _removalWatcher = null;

            _cts?.Cancel();
            if (_pollLoop is not null)
            {
                try { await _pollLoop.ConfigureAwait(false); }
                catch (OperationCanceledException) { /* ожидаемая отмена */ }
            }
            lock (_sync) _knownKeys.Clear();
        }

        private async Task PollLoopAsync(CancellationToken ct)
        {
            IReadOnlyList<RemovableVolumeInfo> lastSnapshot = Array.Empty<RemovableVolumeInfo>();
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    var current = await EnumerateRemovableVolumesAsync(ct).ConfigureAwait(false);
                    DiffAndRaise(lastSnapshot, current);
                    lastSnapshot = current;
                }
                catch (OperationCanceledException) { break; }
                catch (ManagementException) { /* WMI может быть недоступна — ждём следующего цикла */ }

                try { await Task.Delay(PollingInterval, ct).ConfigureAwait(false); }
                catch (OperationCanceledException) { break; }
            }
        }

        private void OnVolumeChanged(ManagementBaseObject targetInstanceEvent, bool isArrival)
        {
            // События WMI приходят из собственного потока — дифф считаем по снимку тома.
            try
            {
                var drive = targetInstanceEvent["TargetInstance"] as ManagementBaseObject;
                var letter = drive?["DriveLetter"] as string;
                if (string.IsNullOrEmpty(letter)) return;

                var snapshot = EnumerateRemovableVolumesAsync(CancellationToken.None).GetAwaiter().GetResult();
                if (isArrival)
                {
                    foreach (var v in snapshot.Where(v => v.DriveLetter.Equals(letter, StringComparison.OrdinalIgnoreCase)))
                        RaiseArrivalFor(v);
                }
                else
                {
                    if (!snapshot.Any(v => v.DriveLetter.Equals(letter, StringComparison.OrdinalIgnoreCase)))
                        RaiseRemovalFor(letter!);
                }
            }
            catch (ManagementException) { /* игнорируем: поллинг подстрахует */ }
        }

        private void DiffAndRaise(IReadOnlyList<RemovableVolumeInfo> oldSnap, IReadOnlyList<RemovableVolumeInfo> newSnap)
        {
            var oldSet = oldSnap.Select(KeyOf).ToHashSet(StringComparer.OrdinalIgnoreCase);
            var newSet = newSnap.Select(KeyOf).ToHashSet(StringComparer.OrdinalIgnoreCase);

            foreach (var v in newSnap.Where(v => !oldSet.Contains(KeyOf(v))))
                RaiseArrivalFor(v);

            foreach (var gone in oldSnap.Where(v => !newSet.Contains(KeyOf(v))))
                RaiseRemovalFor(gone.DriveLetter);
        }

        private void RaiseArrivalFor(RemovableVolumeInfo volume)
        {
            string key = KeyOf(volume);
            lock (_sync)
            {
                if (!_knownKeys.Add(key)) return; // ужеKnown — не дублируем инцидент
            }

            var device = BuildDeviceInfo(volume);
            DeviceArrived?.Invoke(this, new RemovableDeviceEventArgs(device, [volume], isArrival: true));
        }

        private void RaiseRemovalFor(string driveLetter)
        {
            lock (_sync) _knownKeys.Remove(driveLetter);
            var fake = new UsbDeviceInfo
            {
                DeviceId = new UsbDeviceId(0, 0),
                SystemName = driveLetter,
                DeviceClass = UsbDeviceClass.MassStorage,
            };
            var vol = new RemovableVolumeInfo { DeviceId = fake.DeviceId, DriveLetter = driveLetter };
            DeviceRemoved?.Invoke(this, new RemovableDeviceEventArgs(fake, [vol], isArrival: false));
        }

        private static string KeyOf(RemovableVolumeInfo v) =>
            $"{v.SerialNumber ?? v.DriveLetter}|{v.DeviceId}";

        private static UsbDeviceInfo BuildDeviceInfo(RemovableVolumeInfo v) => new()
        {
            DeviceId = v.DeviceId,
            SerialNumber = v.SerialNumber,
            Manufacturer = "USB Mass Storage",
            ProductName = v.VolumeLabel is null ? "USB Drive" : $"USB Drive ({v.VolumeLabel})",
            DeviceClass = UsbDeviceClass.MassStorage,
            Speed = UsbSpeed.HighSpeed,
            HubPath = v.VolumeGuidPath,
            SystemName = v.DriveLetter,
        };

        public Task<IReadOnlyList<RemovableVolumeInfo>> GetRemovableVolumesAsync(CancellationToken cancellationToken = default) =>
            EnumerateRemovableVolumesAsync(cancellationToken);

        /// <summary>
        /// Перечисляет съёмные тома (DriveType=2) и сопоставляет их с USB-дисками
        /// через цепочку ассоциаций Win32_DiskDrive → Win32_DiskPartition → Win32_LogicalDisk.
        /// VID/PID извлекаются из PNPDeviceID вида "USBSTOR\DISK&VEN_...&VID_0951&PID_1666\SERIAL".
        /// </summary>
        private static async Task<IReadOnlyList<RemovableVolumeInfo>> EnumerateRemovableVolumesAsync(CancellationToken ct)
        {
            if (!OperatingSystem.IsWindows())
                return Array.Empty<RemovableVolumeInfo>();

            return await Task.Run(() =>
            {
                var result = new List<RemovableVolumeInfo>();

                // 1. USB-физические диски: буква диска → аппаратные признаки.
                var diskByLetter = new Dictionary<string, (UsbDeviceId Id, string? Sn, string? Pnp)>();
                using (var disks = new ManagementObjectSearcher(
                    @"SELECT DeviceID, PNPDeviceID, SerialNumber FROM Win32_DiskDrive WHERE InterfaceType='USB'"))
                foreach (ManagementObject disk in disks.Get())
                {
                    string pnp = disk["PNPDeviceID"] as string ?? "";
                    var id = TryParseVidPid(pnp);
                    string? sn = (disk["SerialNumber"] as string)?.Trim();
                    string? diskInstance = disk["DeviceID"] as string;

                    // Диск → разделы → логические диски (буква тома).
                    var letters = new List<string>();
                    if (diskInstance is not null)
                    {
                        using var assoc = new ManagementObjectSearcher(
                            $"ASSOCIATORS OF {{Win32_DiskDrive.DeviceID='{diskInstance}'}} WHERE AssocClass=Win32_DiskDriveToDiskPartition");
                        foreach (ManagementObject part in assoc.Get())
                        {
                            using var logs = new ManagementObjectSearcher(
                                $"ASSOCIATORS OF {{Win32_DiskPartition.DeviceID='{part["DeviceID"]}'}} WHERE AssocClass=Win32_LogicalDiskToPartition");
                            foreach (ManagementObject log in logs.Get())
                            {
                                var letter = log["DeviceID"] as string;
                                if (!string.IsNullOrEmpty(letter)) letters.Add(letter);
                            }
                        }
                    }

                    // Резервная привязка: если цепочка ассоциаций не сработала (бывает для FAT32/exFAT),
                    // сопоставляем USB-диски со съёмными логическими дисками по порядку.
                    if (letters.Count == 0 && pnp.Length > 0)
                    {
                        try
                        {
                            using var mp = new ManagementObjectSearcher(
                                @"SELECT DeviceID FROM Win32_LogicalDisk WHERE DriveType=2");
                            foreach (ManagementObject d in mp.Get())
                            {
                                var letter = d["DeviceID"] as string;
                                if (!string.IsNullOrEmpty(letter) && !letters.Contains(letter))
                                    letters.Add(letter);
                            }
                        }
                        catch (ManagementException) { /* игнорируем */ }
                    }

                    foreach (var letter in letters)
                        diskByLetter.TryAdd(letter, (id, string.IsNullOrWhiteSpace(sn) ? null : sn, pnp));
                }

                // 2. Съёмные тома.
                using var volumes = new ManagementObjectSearcher(
                    @"SELECT DeviceID, Caption, Label, FileSystem, Capacity, FreeSpace, DriveType FROM Win32_Volume WHERE DriveType=2");
                foreach (ManagementObject vol in volumes.Get())
                {
                    string letter = vol["Caption"] as string ?? vol["DeviceID"] as string ?? "";
                    if (string.IsNullOrEmpty(letter)) continue;

                    var (id, sn, pnp) = diskByLetter.TryGetValue(letter, out var d)
                        ? d
                        : (new UsbDeviceId(0, 0), null, null);

                    result.Add(new RemovableVolumeInfo
                    {
                        DeviceId = id,
                        SerialNumber = sn,
                        DriveLetter = letter.EndsWith(':') ? letter : letter + ":",
                        VolumeLabel = vol["Label"] as string,
                        FileSystem = vol["FileSystem"] as string ?? "UNKNOWN",
                        TotalBytes = ToInt64(vol["Capacity"]),
                        FreeBytes = ToInt64(vol["FreeSpace"]),
                        VolumeGuidPath = vol["DeviceID"] as string,
                        DeviceType = RemovableDeviceType.UsbFlashDrive,
                    });
                }

                return (IReadOnlyList<RemovableVolumeInfo>)result;
            }, ct).ConfigureAwait(false);
        }

        private static long ToInt64(object? o) => o switch
        {
            null => 0,
            long l => l,
            _ => long.TryParse(o.ToString(), out var v) ? v : 0
        };

        /// <summary>Из "USBSTOR\DISK&VEN_KINGSTON&PROD...&VID_0951&PID_1666\AABBCC" → VID_0951&PID_1666.</summary>
        internal static UsbDeviceId TryParseVidPid(string pnpDeviceId)
        {
            ushort vid = 0, pid = 0;
            foreach (var seg in pnpDeviceId.Split('&'))
            {
                var s = seg.TrimStart('\\');
                if (s.StartsWith("VID_", StringComparison.OrdinalIgnoreCase) &&
                    ushort.TryParse(s.AsSpan(4), System.Globalization.NumberStyles.HexNumber, null, out var v))
                    vid = v;
                else if (s.StartsWith("PID_", StringComparison.OrdinalIgnoreCase) &&
                    ushort.TryParse(s.AsSpan(4), System.Globalization.NumberStyles.HexNumber, null, out var p))
                    pid = p;
            }
            return new UsbDeviceId(vid, pid);
        }

        public async ValueTask DisposeAsync()
        {
            if (_disposed) return;
            _disposed = true;
            await StopAsync().ConfigureAwait(false);
        }
    }
}
