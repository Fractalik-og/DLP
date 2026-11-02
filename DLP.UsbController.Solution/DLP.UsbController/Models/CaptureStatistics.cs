namespace DLP.UsbController.Models
{
    /// <summary>
    /// Статистика текущего захвата для отображения в UI.
    /// </summary>
    public class CaptureStatistics
    {
        public long TotalPackets { get; set; }
        public long CapturedPackets { get; set; }
        public long FilteredOutPackets { get; set; }
        public long ErrorPackets { get; set; }
        public long BytesCaptured { get; set; }

        /// <summary>Заполненность буфера, 0..1.</summary>
        public double BufferUsage => BufferSizeBytes == 0 ? 0 : (double)BytesCaptured / BufferSizeBytes;

        public long BufferSizeBytes { get; set; } = 512L * 1024 * 1024;

        /// <summary>Средняя скорость потока, пакетов/с.</summary>
        public double PacketsPerSecond
        {
            get
            {
                var elapsed = DateTime.UtcNow - StartTime;
                return elapsed.TotalSeconds > 0 ? CapturedPackets / elapsed.TotalSeconds : 0;
            }
        }

        public DateTime StartTime { get; set; } = DateTime.UtcNow;

        public void Reset()
        {
            TotalPackets = 0;
            CapturedPackets = 0;
            FilteredOutPackets = 0;
            ErrorPackets = 0;
            BytesCaptured = 0;
            StartTime = DateTime.UtcNow;
        }

        public override string ToString() =>
            $"Пакетов: {CapturedPackets:N0}, ошибок: {ErrorPackets:N0}, " +
            $"буфер: {BufferUsage:P0}, скорость: {PacketsPerSecond:N0} пак/с";
    }
}
