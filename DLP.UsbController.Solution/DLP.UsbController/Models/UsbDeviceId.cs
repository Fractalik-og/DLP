using DLP.UsbController.Enums;

namespace DLP.UsbController.Models
{
    /// <summary>
    /// Идентификатор USB-устройства: Vendor ID + Product ID.
    /// Реализует IEquatable для использования в словарях и LINQ.
    /// </summary>
    public readonly struct UsbDeviceId : IEquatable<UsbDeviceId>
    {
        public ushort VendorId { get; }
        public ushort ProductId { get; }

        public UsbDeviceId(ushort vendorId, ushort productId)
        {
            VendorId = vendorId;
            ProductId = productId;
        }

        /// <summary>Формат "VID_1234&PID_ABCD" (как в диспетчере устройств Windows).</summary>
        public static UsbDeviceId Parse(string text)
        {
            if (string.IsNullOrWhiteSpace(text))
                throw new ArgumentException("Строка не может быть пустой.", nameof(text));

            var parts = text.Split(new[] { '&', ':' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length != 2)
                throw new FormatException($"Некорректный формат: '{text}'. Ожидается 'VID_xxxx&PID_xxxx'.");

            ushort vid = ParseHex(parts[0], "VID");
            ushort pid = ParseHex(parts[1], "PID");
            return new UsbDeviceId(vid, pid);
        }

        private static ushort ParseHex(string part, string prefix)
        {
            var idx = part.IndexOf(prefix + "_", StringComparison.OrdinalIgnoreCase);
            var hex = idx >= 0 ? part[(idx + prefix.Length + 1)..] : part;
            return Convert.ToUInt16(hex, 16);
        }

        public bool Equals(UsbDeviceId other) =>
            VendorId == other.VendorId && ProductId == other.ProductId;

        public override bool Equals(object? obj) =>
            obj is UsbDeviceId id && Equals(id);

        public override int GetHashCode() =>
            HashCode.Combine(VendorId, ProductId);

        public static bool operator ==(UsbDeviceId left, UsbDeviceId right) => left.Equals(right);
        public static bool operator !=(UsbDeviceId left, UsbDeviceId right) => !left.Equals(right);

        /// <summary>Известные VID производителей анализаторов (пример).</summary>
        public static class KnownVendors
        {
            public const ushort Cypress = 0x04B4;   // Cypress/Infineon (FX2 — Basis, Total Phase...)
            public const ushort TotalPhase = 0x04B4;
            public const ushort Microchip = 0x04D8;
            public const ushort FTDI = 0x0403;
            public const ushort TexasInstruments = 0x0451;
        }

        public override string ToString() => $"VID_{VendorId:X4}&PID_{ProductId:X4}";
    }
}
