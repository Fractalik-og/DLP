using DLP.UsbController.Enums;

namespace DLP.UsbController.Models
{
    /// <summary>
    /// Настройки захвата USB-анализатора.
    /// </summary>
    public class CaptureSettings
    {
        /// <summary>Фильтры захвата (пустой список = захватывать всё).</summary>
        public IReadOnlyList<CaptureFilter> Filters { get; }
            => _filters.AsReadOnly();
        private readonly List<CaptureFilter> _filters = new();

        /// <summary>Максимальный размер буфера захвата, МБ.</summary>
        public int BufferSizeMb { get; set; } = 512;

        /// <summary>Режим буфера: кольцевой (Circular) или до переполнения (Linear).</summary>
        public bool IsRingBuffer { get; set; } = true;

        /// <summary>Захватывать ли SOF-пакеты (обычно шум). </summary>
        public bool CaptureStartOfFrames { get; set; } = false;

        /// <summary>Захватывать данные с ошибкой CRC.</summary>
        public bool CaptureErroneousPackets { get; set; } = true;

        /// <summary>Триггер остановки: остановить при обнаружении пакета, удовлетворяющего фильтру.</summary>
        public CaptureFilter? StopTrigger { get; set; }

        /// <summary>Интерфейсы/порты анализатора (для многопортовых устройств, напр. Total Phase Aardvark).</summary>
        public IReadOnlyList<string> Ports { get; }
            => _ports.AsReadOnly();
        private readonly List<string> _ports = new();

        public void AddFilter(CaptureFilter filter)
        {
            ArgumentNullException.ThrowIfNull(filter);
            _filters.Add(filter);
        }

        public void ClearFilters() => _filters.Clear();

        public void AddPort(string port)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(port);
            _ports.Add(port);
        }

        /// <summary>Возвращает копию настроек (для безопасной передачи в сервис).</summary>
        public CaptureSettings Clone()
        {
            var copy = new CaptureSettings
            {
                BufferSizeMb = BufferSizeMb,
                IsRingBuffer = IsRingBuffer,
                CaptureStartOfFrames = CaptureStartOfFrames,
                CaptureErroneousPackets = CaptureErroneousPackets,
                StopTrigger = StopTrigger
            };
            copy._filters.AddRange(_filters);
            copy._ports.AddRange(_ports);
            return copy;
        }
    }

    /// <summary>
    /// Условие фильтрации пакетов при захвате.
    /// </summary>
    public class CaptureFilter
    {
        public FilterType Type { get; set; } = FilterType.None;

        /// <summary>VID/PID (для типа ByVendorProductId).</summary>
        public UsbDeviceId? DeviceId { get; set; }

        /// <summary>USB-адрес (для типа ByDeviceAddress).</summary>
        public byte? DeviceAddress { get; set; }

        /// <summary>Класс устройства (для типа ByDeviceClass).</summary>
        public UsbDeviceClass? DeviceClass { get; set; }

        /// <summary>Тип транзакции (для типа ByTransactionType).</summary>
        public TransactionType? Transaction { get; set; }

        /// <summary>Номер эндпоинта (для типа ByEndpoint).</summary>
        public byte? EndpointNumber { get; set; }

        /// <summary>Шаблон байтов и маска (для типа ByPayloadPattern), например FF/00 — "любой байт".</summary>
        public byte[]? Pattern { get; set; }
        public byte[]? PatternMask { get; set; }

        /// <summary>Инвертировать условие (исключить вместо включения).</summary>
        public bool Invert { get; set; }

        /// <summary>Проверка, подходит ли пакет под фильтр.</summary>
        public bool Matches(in UsbPacket packet)
        {
            bool result = Type switch
            {
                FilterType.None => true,
                FilterType.ByDeviceAddress => DeviceAddress.HasValue && packet.DeviceAddress == DeviceAddress.Value,
                FilterType.ByTransactionType => Transaction.HasValue && packet.Type == Transaction.Value,
                FilterType.ByEndpoint => EndpointNumber.HasValue && packet.EndpointNumber == EndpointNumber.Value,
                FilterType.ByPayloadPattern => MatchesPattern(packet.Payload.Span),
                _ => true
            };
            return Invert ? !result : result;
        }

        private bool MatchesPattern(ReadOnlySpan<byte> payload)
        {
            if (Pattern is null || PatternMask is null) return false;
            if (payload.Length < Pattern.Length) return false;

            for (int i = 0; i < Pattern.Length; i++)
            {
                if ((payload[i] & PatternMask[i]) != (Pattern[i] & PatternMask[i]))
                    return false;
            }
            return true;
        }

        public override string ToString() =>
            $"{(Invert ? "NOT " : "")}{Type}: {DeviceId?.ToString() ?? DeviceAddress?.ToString() ?? Transaction?.ToString() ?? "any"}";
    }
}
