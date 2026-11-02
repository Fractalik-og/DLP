using DLP.UsbController.Models;

namespace DLP.UsbController.Interfaces
{
    /// <summary>
    /// Интерфейс обнаружения USB-устройств в системе (WMI / SetupAPI / libusb).
    /// Используется модулем DLP-контроля для инвентаризации подключений.
    /// </summary>
    public interface IDeviceWatcher : IDisposable
    {
        /// <summary>Устройство подключено.</summary>
        event EventHandler<DeviceDetectedEventArgs>? DeviceArrived;

        /// <summary>Устройство отключено.</summary>
        event EventHandler<DeviceDetectedEventArgs>? DeviceRemoved;

        /// <summary>Запустить фоновое наблюдение за шиной.</summary>
        void Start();

        /// <summary>Остановить наблюдение.</summary>
        void Stop();

        /// <summary>Список всех подключённых в данный момент USB-устройств.</summary>
        Task<IReadOnlyList<UsbDeviceInfo>> GetConnectedDevicesAsync(CancellationToken cancellationToken = default);
    }
}
