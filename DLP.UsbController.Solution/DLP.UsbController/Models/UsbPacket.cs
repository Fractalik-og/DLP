using DLP.UsbController.Enums;

namespace DLP.UsbController.Models
{
    /// <summary>
    /// Захваченный USB-пакет (одна транзакция на уровне протокола).
    /// </summary>
    public readonly struct UsbPacket
    {
        /// <summary>Сквозной номер пакета в захвате.</summary>
        public long SequenceNumber { get; }

        /// <summary>Метка времени с точностью до наносекунд (от начала захвата).</summary>
        public long TimestampNs { get; }

        /// <summary>Тип транзакции (PID-токен).</summary>
        public TransactionType Type { get; }

        /// <summary>Направление передачи.</summary>
        public TransferDirection Direction { get; }

        /// <summary>USB-адрес целевого устройства (7 бит).</summary>
        public byte DeviceAddress { get; }

        /// <summary>Номер эндпоинта (4 бита).</summary>
        public byte EndpointNumber { get; }

        /// <summary>Номер кадра/микрокадра (11 бит).</summary>
        public ushort FrameNumber { get; }

        /// <summary>Полезная нагрузка пакета (может быть пустой для токенов).</summary>
        public ReadOnlyMemory<byte> Payload { get; }

        /// <summary>Передавалась ли длина в пакете (для DATA — фактическая длина).</summary>
        public bool IsDataLong { get; }

        /// <summary>Ошибка CRC5/CRC16 в пакете.</summary>
        public bool HasCrcError { get; }

        public UsbPacket(
            long sequenceNumber,
            long timestampNs,
            TransactionType type,
            TransferDirection direction,
            byte deviceAddress,
            byte endpointNumber,
            ushort frameNumber,
            ReadOnlyMemory<byte> payload,
            bool isDataLong = false,
            bool hasCrcError = false)
        {
            SequenceNumber = sequenceNumber;
            TimestampNs = timestampNs;
            Type = type;
            Direction = direction;
            DeviceAddress = deviceAddress;
            EndpointNumber = endpointNumber;
            FrameNumber = frameNumber;
            Payload = payload;
            IsDataLong = isDataLong;
            HasCrcError = hasCrcError;
        }

        /// <summary>Время пакета как TimeSpan от начала захвата.</summary>
        public TimeSpan Time => TimeSpan.FromTicks(TimestampNs / 100);

        /// <summary>HEX-представление полезной нагрузки для отображения в UI.</summary>
        public string PayloadHex => Payload.IsEmpty
            ? string.Empty
            : Convert.ToHexString(Payload.Span);

        public override string ToString() =>
            $"#{SequenceNumber} t={Time:hh\\:mm\\:ss\\.FFFFFF} {Type} " +
            $"addr={DeviceAddress:D3} ep={EndpointNumber:D2} len={Payload.Length}";
    }
}
