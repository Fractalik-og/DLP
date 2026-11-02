using System.Text.Json.Serialization;
using DLP.UsbController.Enums;

namespace DLP.UsbController.Models
{
    /// <summary>
    /// Конфигурация политики безопасности агента.
    /// Сериализуется в JSON (policy.json), поставляется с центра либо редактируется локально.
    /// </summary>
    public sealed class DlpPolicyConfig
    {
        /// <summary>Режим работы: 0 = Monitor (только журнал), 1 = ReadOnly, 2 = Quarantine.</summary>
        [JsonConverter(typeof(JsonStringEnumConverter))]
        public EnforcementAction DefaultAction { get; set; } = EnforcementAction.SetReadOnly;

        /// <summary>Максимальный размер файла для анализа содержимого, МБ.</summary>
        public int MaxFileScanSizeMb { get; set; } = 20;

        /// <summary>Ограничение на глубину дерева каталогов.</summary>
        public int MaxDirectoryDepth { get; set; } = 12;

        /// <summary>Ограничение общего числа файлов на том (защита от сканирования «мусорных» архивов).</summary>
        public int MaxFilesPerVolume { get; set; } = 50_000;

        /// <summary>Расширения текстовых документов, анализируемых регулярными выражениями.</summary>
        public string[] TextFileExtensions { get; set; } =
            [".txt", ".csv", ".log", ".md", ".rtf", ".xml", ".json",
             ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".odt", ".ods"];

        /// <summary>Ключевые слова словаря по категориям (регистронезависимый поиск).</summary>
        public Dictionary<FindingCategory, string[]> KeywordDictionaries { get; set; } = new()
        {
            [FindingCategory.ClassifiedMarking] = ["СЕКРЕТНО", "Совершенно секретно", "ДСП", "Для служебного пользования", "Гриф"],
            [FindingCategory.PersonalData] = ["персональные данные", "паспорт РФ", "СНИЛС", "ИНН", "ФИО"],
            [FindingCategory.Financial] = ["банковская карта", "расчётный счёт", "реквизиты", "платёжное поручение"],
        };

        /// <summary>VID/PID устройства в белом списке (разрешены без ограничений), формат "VID_1234&PID_ABCD".</summary>
        public string[] WhitelistedDeviceIds { get; set; } = [];

        /// <summary>Серийные номера в белом списке (корпоративные носители).</summary>
        public string[] WhitelistedSerialNumbers { get; set; } = [];

        /// <summary>URL центрального сервера DLP для отправки инцидентов.</summary>
        public string CentralServerUrl { get; set; } = "https://dlp-server.corp.local:8443/api/incidents";

        /// <summary>Каталог карантина.</summary>
        public string QuarantineDirectory { get; set; } = @"C:\ProgramData\DlpAgent\Quarantine";

        /// <summary>Файл NDJSON-журнала инцидентов.</summary>
        public string IncidentLogPath { get; set; } = @"C:\ProgramData\DlpAgent\incidents.ndjson";

        /// <summary>Интервал повторной отправки неотвезённых инцидентов, сек.</summary>
        public int ResendIntervalSeconds { get; set; } = 60;

        public bool IsWhitelisted(UsbDeviceId id, string? serial) =>
            WhitelistedDeviceIds.Any(x => string.Equals(x, id.ToString(), StringComparison.OrdinalIgnoreCase)) ||
            (serial is not null && WhitelistedSerialNumbers.Any(x => string.Equals(x, serial, StringComparison.OrdinalIgnoreCase)));
    }
}
