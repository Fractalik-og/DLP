namespace DLP.UsbController.Enums
{
    /// <summary>
    /// Статус USB-анализатора (аппаратного захвата).
    /// </summary>
    public enum AnalyzerStatus
    {
        /// <summary>Устройство не подключено.</summary>
        Disconnected = 0,
        /// <summary>Подключено, готово к работе.</summary>
        Ready,
        /// <summary>Идёт захват трафика.</summary>
        Capturing,
        /// <summary>Захват приостановлен.</summary>
        Paused,
        /// <summary>Переполнение буфера — часть данных потеряна.</summary>
        BufferOverflow,
        /// <summary>Аппаратная или драйверная ошибка.</summary>
        Error
    }
}
