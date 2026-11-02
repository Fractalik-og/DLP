namespace DLP.UsbController.Enums
{
    /// <summary>
    /// Тип фильтра для захвата USB-трафика.
    /// </summary>
    public enum FilterType
    {
        /// <summary>Фильтр не задан (принимать всё).</summary>
        None = 0,
        /// <summary>По VID/PID устройства.</summary>
        ByVendorProductId,
        /// <summary>По USB-адресу устройства на шине.</summary>
        ByDeviceAddress,
        /// <summary>По классу устройства.</summary>
        ByDeviceClass,
        /// <summary>По типу транзакции (SETUP/IN/OUT...).</summary>
        ByTransactionType,
        /// <summary>По номеру эндпоинта.</summary>
        ByEndpoint,
        /// <summary>По содержимому пакета (маска байтов).</summary>
        ByPayloadPattern
    }
}
