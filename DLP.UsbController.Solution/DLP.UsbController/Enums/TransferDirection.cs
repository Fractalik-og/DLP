namespace DLP.UsbController.Enums
{
    /// <summary>
    /// Направление передачи данных на USB-шине.
    /// </summary>
    public enum TransferDirection
    {
        /// <summary>Направление не определено (например, SOF).</summary>
        Unknown = 0,
        /// <summary>Host → Device.</summary>
        HostToDevice,
        /// <summary>Device → Host.</summary>
        DeviceToHost,
        /// <summary>Широковещательная/служебная передача.</summary>
        Broadcast
    }
}
