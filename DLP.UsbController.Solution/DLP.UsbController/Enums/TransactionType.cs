namespace DLP.UsbController.Enums
{
    /// <summary>
    /// Тип USB-транзакции (для протокольного анализа).
    /// </summary>
    public enum TransactionType
    {
        Unknown = 0,
        /// <summary>Токен SETUP — настройка передачи.</summary>
        Setup,
        /// <summary>Токен IN — запрос данных устройством → хост.</summary>
        In,
        /// <summary>Токен OUT — передача данных хост → устройство.</summary>
        Out,
        /// <summary>Токен SOF (Start Of Frame).</summary>
        StartOfFrame,
        /// <summary>PING — проверка готовности устройства (HighSpeed).</summary>
        Ping,
        /// <summary>PRE — преамбула для Low/FullSpeed на HighSpeed-шине.</summary>
        Preamble,
        /// <summary>Данные DATA0/DATA1/DATA2/MDATA.</summary>
        Data,
        /// <summary>Подтверждение ACK.</summary>
        Acknowledge,
        /// <summary>Отрицание NAK.</summary>
        NotAcknowledge,
        /// <summary>Ошибка STALL.</summary>
        Stall,
        /// <summary>Раздел кадра (EOF) или ошибка CRC — ERR.</summary>
        Error
    }
}
