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
        Unknown = 0,
        /// <summary>Персональные данные (ПДн): СНИЛС, ИНН, паспорт РФ.</summary>
        PersonalData,
        /// <summary>Банковские реквизиты (номер карты по Луну, расчётные счета).</summary>
        Financial,
        /// <summary>Документы с грифом секретности («СЕКРЕТНО», «ДСП» и т.п.).</summary>
        ClassifiedMarking,
        /// <summary>Прочие ключевые слова из словаря политики.</summary>
        Keyword,
    }

    /// <summary>Мера принуждения, применённая агентом при срабатывании политики.</summary>
    public enum EnforcementAction
    {
        /// <summary>Ничего не делать (режим мониторинга / dry-run).</summary>
        None = 0,
        /// <summary>Перевод устройства в режим «только чтение» (реестр: USBWriteProtect).</summary>
        SetReadOnly,
        /// <summary>Возврат устройству права записи.</summary>
        RestoreReadWrite,
        /// <summary>Изъятие скомпрометированных файлов в карантин с подменой заглушками.</summary>
        QuarantineFiles,
    }

    /// <summary>Стадии жизненного цикла обработки устройства агентом.</summary>
    public enum DeviceProcessingStage
    {
        Idle = 0,
        Detected,
        MatchingVolumes,
        Scanning,
        Enforcing,
        Completed,
        Failed,
    }

    /// <summary>Исход отправки инцидента на центральный сервер DLP.</summary>
    public enum IncidentDeliveryStatus
    {
        Queued = 0,
        Delivered,
        Failed,
    }

    /// <summary>Уровень серьёзности инцидента.</summary>
    public enum IncidentSeverity
    {
        Info = 0,
        Low,
        Medium,
        High,
        Critical,
    }

    /// <summary>Состояние USB-устройства в интерфейсе агента (паттерн State).</summary>
    public enum DeviceState
    {
        /// <summary>Устройство обнаружено, ожидает обработки.</summary>
        Connected = 0,
        /// <summary>Выполняется обход и анализ файлов.</summary>
        Scanning,
        /// <summary>Проверено, нарушений нет — разрешено.</summary>
        Allowed,
        /// <summary>Запись ограничена (режим «только чтение»).</summary>
        Blocked,
        /// <summary>Обнаружены конфиденциальные файлы, часть изъята в карантин.</summary>
        Quarantined,
        /// <summary>Устройство извлечено.</summary>
        Disconnected,
        /// <summary>Ошибка обработки (носитель недоступен и т.п.).</summary>
        Error,
    }
}
