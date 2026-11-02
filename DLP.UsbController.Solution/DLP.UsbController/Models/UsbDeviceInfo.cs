using DLP.UsbController.Enums;

namespace DLP.UsbController.Models
{
    /// <summary>
    /// Описание USB-устройства, обнаруженного в системе (для модуля контроля/инвентаризации).
    /// </summary>
    public class UsbDeviceInfo
    {
        /// <summary>VID/PID устройства.</summary>
        public UsbDeviceId DeviceId { get; set; }

        /// <summary>Серийный номер (iSerialNumber из дескриптора строки).</summary>
        public string? SerialNumber { get; set; }

        /// <summary>Производитель (iManufacturer).</summary>
        public string? Manufacturer { get; set; }

        /// <summary>Название продукта (iProduct).</summary>
        public string? ProductName { get; set; }

        /// <summary>Класс устройства.</summary>
        public UsbDeviceClass DeviceClass { get; set; }

        /// <summary>Достигнутая скорость соединения.</summary>
        public UsbSpeed Speed { get; set; }

        /// <summary>USB-адрес устройства на шине (1..127).</summary>
        public byte Address { get; set; }

        /// <summary>Путь к контроллеру/хабу, например "PCI\ROOT_HUB\0002:0001".</summary>
        public string? HubPath { get; set; }

        /// <summary>Системное имя устройства (\\?\usb#vid_...).</summary>
        public string? SystemName { get; set; }

        /// <summary>Дата и время подключения.</summary>
        public DateTime ConnectedAt { get; set; } = DateTime.UtcNow;

        /// <summary>Активно ли устройство сейчас.</summary>
        public bool IsConnected { get; set; } = true;

        public override string ToString() =>
            $"{ProductName ?? DeviceId.ToString()} [{DeviceId}] — {Speed}, адрес {Address}";
    }
}
