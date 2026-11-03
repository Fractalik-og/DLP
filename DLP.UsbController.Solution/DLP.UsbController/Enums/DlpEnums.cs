using System.ComponentModel;

namespace DLP.UsbController.Enums
{
    /// <summary>Тип обнаруженного съёмного устройства.</summary>
    public enum RemovableDeviceType
    {
        Unknown = 0,
        /// <summary>USB Mass Storage (флеш-накопитель, внешний HDD/SSD).</summary>
        UsbFlashDrive,
        /// <summary>Внешний оптический привод.</summary>
        OpticalDrive,
        /// <summary>Karts/SD-ридеры и прочее.</summary>
        CardReader,
    }

    /// <summary>Категории конфиденциальной информации, которые ищет статический анализ.</summary>
    public enum FindingCategory
    {
        [Description("Прочее")]
        Unknown = 0,
        /// <summary>Персональные данные (ПДн): СНИЛС, ИНН, паспорт РФ.</summary>
        [Description("Персональные данные")]
        PersonalData,
        /// <summary>Банковские реквизиты (номер карты по Луну, расчётные счета).</summary>
        [Description("Банковские реквизиты")]
        Financial,
        /// <summary>Документы с грифом секретности («СЕКРЕТНО», «ДСП» и т.п.).</summary>
        [Description("Гриф секретности")]
        ClassifiedMarking,
        /// <summary>Прочие ключевые слова из словаря политики.</summary>
        [Description("Ключевые слова")]
        Keyword,
    }

    /// <summary>Мера принуждения, применённая агентом при срабатывании политики.</summary>
    public enum EnforcementAction
    {
        /// <summary>Ничего не делать (режим мониторинга / dry-run).</summary>
        [Description("Нет")]
        None = 0,
        /// <summary>Перевод устройства в режим «только чтение» (реестр: USBWriteProtect).</summary>
        [Description("Только чтение")]
        SetReadOnly,
        /// <summary>Возврат устройству права записи.</summary>
        [Description("Запись разрешена")]
        RestoreReadWrite,
        /// <summary>Изъятие скомпрометированных файлов в карантин с подменой заглушками.</summary>
        [Description("Карантин файлов")]
        QuarantineFiles,
    }

    /// <summary>Стадии жизненного цикла обработки устройства агентом.</summary>
    public enum DeviceProcessingStage
    {
        [Description("Ожидание")]
        Idle = 0,
        [Description("Обнаружено")]
        Detected,
        [Description("Поиск тома")]
        MatchingVolumes,
        [Description("Сканирование")]
        Scanning,
        [Description("Принуждение")]
        Enforcing,
        [Description("Завершено")]
        Completed,
        [Description("Ошибка")]
        Failed,
    }

    /// <summary>Исход отправки инцидента на центральный сервер DLP.</summary>
    public enum IncidentDeliveryStatus
    {
        [Description("В очереди")]
        Queued = 0,
        [Description("Отправлен")]
        Delivered,
        [Description("Ошибка")]
        Failed,
    }

    /// <summary>Уровень серьёзности инцидента.</summary>
    public enum IncidentSeverity
    {
        [Description("Инфо")]
        Info = 0,
        [Description("Низкая")]
        Low,
        [Description("Средняя")]
        Medium,
        [Description("Высокая")]
        High,
        [Description("Критическая")]
        Critical,
    }

    /// <summary>Состояние USB-устройства в интерфейсе агента (паттерн State).</summary>
    public enum DeviceState
    {
        /// <summary>Устройство обнаружено, ожидает обработки.</summary>
        [Description("Подключено")]
        Connected = 0,
        /// <summary>Выполняется обход и анализ файлов.</summary>
        [Description("Сканируется")]
        Scanning,
        /// <summary>Проверено, нарушений нет — разрешено.</summary>
        [Description("Разрешено")]
        Allowed,
        /// <summary>Запись ограничена (режим «только чтение»).</summary>
        [Description("Блокировка записи")]
        Blocked,
        /// <summary>Обнаружены конфиденциальные файлы, часть изъята в карантин.</summary>
        [Description("Карантин")]
        Quarantined,
        /// <summary>Устройство извлечено.</summary>
        [Description("Отключено")]
        Disconnected,
        /// <summary>Ошибка обработки (носитель недоступен и т.п.).</summary>
        [Description("Ошибка")]
        Error,
    }
}
