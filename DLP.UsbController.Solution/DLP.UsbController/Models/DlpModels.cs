using DLP.UsbController.Enums;

namespace DLP.UsbController.Models
{
    /// <summary>
    /// Съёмный накопитель, сопоставленный с логическим томом ОС.
    /// Связывает аппаратные признаки (VID/PID/SN) с точками монтирования.
    /// </summary>
    public sealed class RemovableVolumeInfo
    {
        /// <summary>Аппаратный идентификатор устройства.</summary>
        public required UsbDeviceId DeviceId { get; init; }

        /// <summary>Серийный номер устройства (главный признак уникальности).</summary>
        public string? SerialNumber { get; init; }

        /// <summary>Буква диска, например "E:". Always with colon.</summary>
        public required string DriveLetter { get; init; }

        /// <summary>Метка тома.</summary>
        public string? VolumeLabel { get; init; }

        /// <summary>Файловая система (NTFS/FAT32/exFAT…).</summary>
        public string FileSystem { get; init; } = "UNKNOWN";

        public long TotalBytes { get; init; }
        public long FreeBytes { get; init; }

        /// <summary>Идентификатор тома Windows ("\\\\?\\Volume{GUID}\\").</summary>
        public string? VolumeGuidPath { get; init; }

        public RemovableDeviceType DeviceType { get; init; } = RemovableDeviceType.UsbFlashDrive;

        public long UsedBytes => TotalBytes - FreeBytes;

        public override string ToString() =>
            $"{DriveLetter} ({VolumeLabel ?? "без метки"}, {FileSystem}) ← {DeviceId}, SN={SerialNumber ?? "—"}";
    }

    /// <summary>Один фрагмент-«хит», найденный сканером содержимого.</summary>
    public sealed class ContentFinding
    {
        public FindingCategory Category { get; init; }

        /// <summary>Относительный путь файла на накопителе.</summary>
        public required string RelativePath { get; init; }

        /// <summary>Замаскированный фрагмент (например "4081 **** **** 1234"), чтобы не светить ПДн в логах.</summary>
        public required string MaskedMatch { get; init; }

        /// <summary>Название сработавшего правила/словаря.</summary>
        public required string RuleName { get; init; }

        public int LineNumber { get; init; }

        public IncidentSeverity Severity { get; init; } = IncidentSeverity.Medium;

        public override string ToString() => $"[{Category}] {RuleName}: {MaskedMatch} @ {RelativePath}:{LineNumber}";
    }

    /// <summary>Результат статического анализа одного файла.</summary>
    public sealed class FileScanResult
    {
        public required string RelativePath { get; init; }
        public long SizeBytes { get; set; }
        public List<ContentFinding> Findings { get; init; } = [];
        public bool IsCommitted => Findings.Count > 0;
        public string? SkipReason { get; set; } // binary/too large/unsupported
    }

    /// <summary>Реестр-параметры конкретного устройства для возврата исходного состояния.</summary>
    public sealed class DeviceWritePolicyState
    {
        public required UsbDeviceId DeviceId { get; init; }
        public string? SerialNumber { get; init; }

        /// <summary>Значение USBWriteProtect до вмешательства агента (null — параметр отсутствовал).</summary>
        public int? OriginalWriteProtectValue { get; set; }

        public bool IsReadOnlyNow { get; set; }
        public DateTime? AppliedAtUtc { get; set; }
        public DateTime? RestoredAtUtc { get; set; }
    }

    /// <summary>Запись об изъятых файлах (для отчёта и потенциального восстановления).</summary>
    public sealed class QuarantineRecord
    {
        public required string OriginalFullPath { get; init; }
        public required string QuarantinedFilePath { get; init; }
        public required string StubFilePath { get; init; }
        public required string Sha256Original { get; init; }
        public long SizeBytes { get; init; }
        public DateTime QuarantinedAtUtc { get; init; } = DateTime.UtcNow;
        public IReadOnlyList<ContentFinding> Findings { get; init; } = [];
    }

    /// <summary>
    /// Инцидент безопасности — структурированная запись, сериализуемая в NDJSON-журнал
    /// и отправляемая на центральный сервер DLP.
    /// </summary>
    public sealed class SecurityIncident
    {
        public string Id { get; init; } = Guid.NewGuid().ToString("N");
        public DateTimeOffset Timestamp { get; init; } = DateTimeOffset.UtcNow;

        public required string EventType { get; init; } // DeviceArrival / PolicyViolation / Enforcement / DeviceRemoval...
        public IncidentSeverity Severity { get; init; } = IncidentSeverity.Medium;

        // ---- идентификация устройства ----
        public string? VidPid { get; init; }
        public string? SerialNumber { get; init; }
        public string? ProductName { get; init; }
        public string? Manufacturer { get; init; }
        public string? DriveLetters { get; init; }

        // ---- контекст станции ----
        public string HostName { get; init; } = Environment.MachineName;
        public string UserName { get; init; } = Environment.UserName;

        // ---- подробности ----
        public string? Description { get; init; }
        public EnforcementAction ActionApplied { get; init; } = EnforcementAction.None;
        public int FindingsCount { get; init; }
        public IReadOnlyList<ContentFinding> Findings { get; init; } = [];
        public IReadOnlyList<QuarantineRecord> QuarantinedFiles { get; init; } = [];

        public IncidentDeliveryStatus DeliveryStatus { get; set; } = IncidentDeliveryStatus.Queued;
        public DateTime? DeliveredAtUtc { get; set; }
        public string? DeliveryError { get; set; }
    }

    /// <summary>Сводка по обработанному подключению (для UI).</summary>
    public sealed class ScanSessionSummary
    {
        public required RemovableVolumeInfo Volume { get; init; }
        public DateTime StartedAtUtc { get; init; }
        public DateTime? FinishedAtUtc { get; set; }
        public int FilesScanned { get; set; }
        public int FilesSkipped { get; set; }
        public int FindingsTotal { get; set; }
        public Dictionary<FindingCategory, int> FindingsByCategory { get; } = [];
        public EnforcementAction ActionApplied { get; set; } = EnforcementAction.None;
        public DeviceProcessingStage Stage { get; set; } = DeviceProcessingStage.Idle;
        public int IncidentsLogged { get; set; }
        public string? LastError { get; set; }
    }
}
