using DLP.UsbController.Enums;
using DLP.UsbController.Models;

namespace DLP.UsbController.Interfaces
{
    /// <summary>
    /// Основной интерфейс USB-анализатора — аппаратно-независимое API захвата.
    /// Реализации: эмулятор (для тестов UI), драйвер конкретного анализатора
    /// (Total Phase, Ellisys, BEAGLE, self-hosted FX2 и т.д.).
    /// </summary>
    public interface IUsbAnalyzer : IDisposable
    {
        /// <summary>Текущий статус устройства.</summary>
        AnalyzerStatus Status { get; }

        /// <summary>Информация о самом анализаторе (модель, прошивка).</summary>
        string DeviceDescription { get; }

        /// <summary>Изменение статуса (для подписки UI).</summary>
        event EventHandler<AnalyzerStatusChangedEventArgs>? StatusChanged;

        /// <summary>Новый пакет поступил из буфера захвата.</summary>
        event EventHandler<PacketCapturedEventArgs>? PacketCaptured;

        /// <summary>Обнаружено подключённое USB-устройство на контролируемом порту.</summary>
        event EventHandler<DeviceDetectedEventArgs>? DeviceDetected;

        /// <summary>Подключение к анализатору.</summary>
        Task ConnectAsync(CancellationToken cancellationToken = default);

        /// <summary>Отключение от анализатора.</summary>
        Task DisconnectAsync();

        /// <summary>Запуск захвата с указанными настройками.</summary>
        Task StartCaptureAsync(CaptureSettings settings, CancellationToken cancellationToken = default);

        /// <summary>Остановка захвата.</summary>
        Task StopCaptureAsync();

        /// <summary>Пауза/возобновление захвата.</summary>
        Task SetPausedAsync(bool paused);

        /// <summary>Прочитать накопленные пакеты из буфера (для последующей обработки/экспорта).</summary>
        /// <remarks>
        /// Реализациям-итераторам (async IAsyncEnumerable) необходимо пометить параметр
        /// атрибутом [EnumeratorCancellation], чтобы токен, переданный в GetAsyncEnumerator(),
        /// корректно доходил до тела итератора.
        /// </remarks>
        IAsyncEnumerable<UsbPacket> ReadPacketsAsync(CancellationToken cancellationToken = default);

        /// <summary>Экспорт захвата в файл (например, .csv или бинарный дамп).</summary>
        Task ExportAsync(string filePath, CancellationToken cancellationToken = default);
    }

    /// <summary>Данные события изменения статуса.</summary>
    public class AnalyzerStatusChangedEventArgs : EventArgs
    {
        public AnalyzerStatus OldStatus { get; }
        public AnalyzerStatus NewStatus { get; }
        public string? Message { get; }

        public AnalyzerStatusChangedEventArgs(AnalyzerStatus oldStatus, AnalyzerStatus newStatus, string? message = null)
        {
            OldStatus = oldStatus;
            NewStatus = newStatus;
            Message = message;
        }
    }

    /// <summary>Данные события «пакет захвачен».</summary>
    public class PacketCapturedEventArgs : EventArgs
    {
        public UsbPacket Packet { get; }
        public PacketCapturedEventArgs(UsbPacket packet) => Packet = packet;
    }

    /// <summary>Данные события «обнаружено устройство».</summary>
    public class DeviceDetectedEventArgs : EventArgs
    {
        public UsbDeviceInfo Device { get; }
        public bool IsArrival { get; } // true — подключение, false — отключение

        public DeviceDetectedEventArgs(UsbDeviceInfo device, bool isArrival)
        {
            Device = device;
            IsArrival = isArrival;
        }
    }
}
