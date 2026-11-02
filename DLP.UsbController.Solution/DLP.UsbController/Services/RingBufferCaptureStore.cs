using DLP.UsbController.Enums;
using DLP.UsbController.Interfaces;
using DLP.UsbController.Models;

namespace DLP.UsbController.Services
{
    /// <summary>
    /// Кольцевой буфер захваченных пакетов с потокобезопасной записью
    /// и ограничениями по объёму памяти.
    /// </summary>
    public sealed class RingBufferCaptureStore : ICaptureStore
    {
        private readonly object _sync = new();
        private readonly Queue<UsbPacket> _queue = new();
        private readonly int _maxPackets;
        private long _totalAdded;

        public CaptureStatistics Statistics { get; } = new();

        public RingBufferCaptureStore(int maxPackets = 1_000_000)
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(maxPackets, 1);
            _maxPackets = maxPackets;
        }

        public long Count
        {
            get { lock (_sync) return _queue.Count; }
        }

        public void Add(in UsbPacket packet)
        {
            lock (_sync)
            {
                _queue.Enqueue(packet);
                _totalAdded++;
                Statistics.CapturedPackets = _totalAdded;
                Statistics.TotalPackets = _totalAdded;
                Statistics.BytesCaptured += packet.Payload.Length;
                if (packet.HasCrcError) Statistics.ErrorPackets++;

                while (_queue.Count > _maxPackets)
                    _queue.Dequeue();
            }
        }

        public IReadOnlyList<UsbPacket> GetRange(long startIndex, int count)
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(startIndex, 0);
            ArgumentOutOfRangeException.ThrowIfLessThan(count, 0);

            lock (_sync)
            {
                var list = new List<UsbPacket>(Math.Min(count, _queue.Count));
                long skipped = 0;
                foreach (var p in _queue)
                {
                    if (skipped++ < startIndex) continue;
                    if (list.Count >= count) break;
                    list.Add(p);
                }
                return list;
            }
        }

        public IEnumerable<UsbPacket> Query(CaptureFilter filter)
        {
            ArgumentNullException.ThrowIfNull(filter);
            List<UsbPacket> snapshot;
            lock (_sync)
            {
                // Снимок буфера под блокировкой — фильтрация вне замка безопасна.
                snapshot = _queue.ToList();
            }
            return snapshot.Where(p => filter.Matches(in p));
        }

        public void Clear()
        {
            lock (_sync)
            {
                _queue.Clear();
                Statistics.Reset();
            }
        }
    }
}
