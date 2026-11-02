namespace DLP.UsbController.Enums
{
    /// <summary>
    /// Тип USB-устройства (класс устройства из дескриптора).
    /// </summary>
    public enum UsbDeviceClass : byte
    {
        /// <summary>Определяется на уровне интерфейсов.</summary>
        DefinedByInterface = 0x00,
        Audio = 0x01,
        CdcCommunications = 0x02,
        Hid = 0x03,
        Physical = 0x05,
        Image = 0x06,
        Printer = 0x07,
        MassStorage = 0x08,
        Hub = 0x09,
        CdcData = 0x0A,
        SmartCard = 0x0B,
        ContentSecurity = 0x0D,
        Video = 0x0E,
        PersonalHealthcare = 0x0F,
        AudioVideoDevices = 0x10,
        Billboard = 0x11,
        UsbTypeCBridge = 0x12,
        /// <summary>Diagnostic Device (в т.ч. USB-анализаторы).</summary>
        DiagnosticDevice = 0xDC,
        WirelessController = 0xE0,
        Miscellaneous = 0xEF,
        ApplicationSpecific = 0xFE,
        VendorSpecific = 0xFF
    }
}
