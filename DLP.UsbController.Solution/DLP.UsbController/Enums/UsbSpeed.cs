namespace DLP.UsbController.Enums
{
    /// <summary>
    /// Скорость USB-соединения (согласно спецификации USB).
    /// </summary>
    public enum UsbSpeed
    {
        Unknown = 0,
        /// <summary>USB 1.0/1.1 — 1.5 Мбит/с.</summary>
        LowSpeed = 1,
        /// <summary>USB 1.1 — 12 Мбит/с.</summary>
        FullSpeed = 2,
        /// <summary>USB 2.0 — 480 Мбит/с.</summary>
        HighSpeed = 3,
        /// <summary>USB 3.0/3.1 Gen1 — 5 Гбит/с.</summary>
        SuperSpeed = 4,
        /// <summary>USB 3.1 Gen2 — 10 Гбит/с.</summary>
        SuperSpeedPlus = 5,
        /// <summary>USB 3.2 Gen2x2 — 20 Гбит/с.</summary>
        SuperSpeedGen2x2 = 6,
        /// <summary>USB4 — 40 Гбит/с.</summary>
        Usb4 = 7
    }
}
