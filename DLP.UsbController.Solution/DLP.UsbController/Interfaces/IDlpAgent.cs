using DLP.UsbController.Enums;
using DLP.UsbController.Models;

namespace DLP.UsbController.Interfaces
{
    /// <summary>Аргументы события подключения/отключения съёмного накопителя.</summary>
    public class RemovableDeviceEventArgs : EventArgs
    {
        public UsbDeviceInfo Device { get; }
        public IReadOnlyList<RemovableVolumeInfo> Volumes { get; }
        public bool IsArrival { get; }

        public RemovableDeviceEventArgs(UsbDeviceInfo device, IReadOnlyList<RemovableVolumeInfo> volumes, bool isArrival)
        {
            Device = device;
            Volumes = volumes;
            IsArrival = isArrival;
        }
    }

    /// <summary>
    /// Наблюдатель за съёмными USB-накопителями через подписку на события подсистемы WMI
    /// (__InstanceCreationEvent/__InstanceDeletionEvent по классам Win32_Volume / Win32_LogicalDiskToUSB).
    /// Реализация — <c>WmiRemovableDeviceWatcher</c> (только Windows).
    /// </summary>
    public interface IRemovableDeviceWatcher : IAsyncDisposable
    {
        event EventHandler<RemovableDeviceEventArgs>? DeviceArrived;
        event EventHandler<RemovableDeviceEventArgs>? DeviceRemoved;

        /// <summary>Период поллинга WMI-запросов.</summary>
        TimeSpan PollingInterval { get; set; }

        void Start();
        Task StopAsync();

        /// <summary>Синхронная инвентаризация: съёмные тома + сопоставление с USB-устройствами.</summary>
        Task<IReadOnlyList<RemovableVolumeInfo>> GetRemovableVolumesAsync(CancellationToken cancellationToken = default);
    }

    /// <summary>
    /// Статический анализатор файлового содержимого: регулярные выражения + словари ключевых слов.
    /// </summary>
    public interface IContentScanner
    {
        /// <summary>Полное имя правила (regex или словарь), при срабатывании которого файл считается скомпрометированным.</summary>
        IReadOnlyList<ScanRule> Rules { get; }

        /// <summary>Просканировать один файл, вернуть находки (маскированные).</summary>
        Task<FileScanResult> ScanFileAsync(string fullPath, string relativePath, CancellationToken cancellationToken = default);

        /// <summary>Рекурсивно просканировать том; прогресс — через callback.</summary>
        IAsyncEnumerable<FileScanResult> ScanVolumeAsync(
            RemovableVolumeInfo volume,
            IProgress<ScanProgress>? progress = null,
            CancellationToken cancellationToken = default);
    }

    public sealed record ScanRule(string Name, FindingCategory Category, IncidentSeverity Severity, RuleKind Kind, string Pattern);

    public enum RuleKind { Regex, KeywordDictionary }

    public sealed record ScanProgress(int FilesScanned, int FilesSkipped, int FindingsSoFar, string CurrentFile);

    /// <summary>
    /// Модуль применения мер принуждения: перевод томов в «только чтение»
    /// (реестр: HKLM\SYSTEM\CurrentControlSet\Control\StorageDevicePolicies\WriteProtect)
    /// и карантине изъятие файлов с подменой заглушками.
    /// </summary>
    public interface IEnforcementModule
    {
        /// <summary>Программная модификация ключа реестра: R/O для указанного VID/PID (или всех storage).</summary>
        Task<bool> SetReadOnlyAsync(UsbDeviceId deviceId, string? serialNumber, CancellationToken cancellationToken = default);

        /// <summary>Восстановить права записи (возврат исходного значения параметра реестра).</summary>
        Task<bool> RestoreReadWriteAsync(UsbDeviceId deviceId, string? serialNumber, CancellationToken cancellationToken = default);

        /// <summary>Изъять перечисленные файлы в карантин, на их место поместить файлы-заглушки.</summary>
        Task<IReadOnlyList<QuarantineRecord>> QuarantineFilesAsync(
            IEnumerable<string> filePaths,
            IReadOnlyDictionary<string, IReadOnlyList<ContentFinding>> findingsByFile,
            CancellationToken cancellationToken = default);

        /// <summary>Текст уведомления о применении политики (файл-заглушка).</summary>
        string StubTemplate { get; set; }
    }

    /// <summary>
    /// Журнал инцидентов: структурированное сохранение в формате NDJSON
    /// (одна JSON-запись в строке) + очередь отправки на центральный сервер DLP.
    /// </summary>
    public interface IIncidentLogger : IAsyncDisposable
    {
        /// <summary>Записать инцидент в локальный NDJSON-журнал и поставить в очередь отправки.</summary>
        Task LogAsync(SecurityIncident incident, CancellationToken cancellationToken = default);

        /// <summary>Имитация доставки на центральный сервер (в prod — HTTPS POST с retry/backoff).</summary>
        Task<IncidentDeliveryStatus> DeliverAsync(SecurityIncident incident, CancellationToken cancellationToken = default);

        /// <summary>Прочитать последние N записей журнала (для UI).</summary>
        Task<IReadOnlyList<SecurityIncident>> ReadRecentAsync(int count, CancellationToken cancellationToken = default);

        event EventHandler<SecurityIncident>? IncidentLogged;
    }
}
