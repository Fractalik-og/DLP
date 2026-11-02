using System.Runtime.CompilerServices;
using DLP.UsbController.Enums;
using DLP.UsbController.Interfaces;
using DLP.UsbController.Models;

namespace DLP.UsbController.Services
{
    /// <summary>
    /// Эмулятор USB-анализатора: генерирует синтетический трафик,
    /// позволяя разрабатывать и тестировать UI без аппаратного устройства.
    /// Замените на реальную реализацию (TotPhase API, libusb, WinUSB) позже.
    /// </summary>
    public sealed class EmulatedUsbAnalyzer : IUsbAnalyzer
    {
        private readonly CancellationTokenSource _cts = new();
        private readonly Random _rng = new();
        private CancellationTokenSource? _captureCts;
        private Task? _captureLoop;
        private long _sequence;
        private AnalyzerStatus _status = AnalyzerStatus.Disconnected;
        private volatile bool _paused;

        public AnalyzerStatus Status => _status;
        public string DeviceDescription => "Emulated USB Analyzer v1.0 (DLP.UsbController)";

        public event EventHandler<AnalyzerStatusChangedEventArgs>? StatusChanged;
        public event EventHandler<PacketCapturedEventArgs>? PacketCaptured;
        public event EventHandler<DeviceDetectedEventArgs>? DeviceDetected;

        public async Task ConnectAsync(CancellationToken cancellationToken = default)
        {
            await Task.Delay(300, cancellationToken); // имитация открытия устройства
            SetStatus(AnalyzerStatus.Ready, "Эмулятор подключён");
        }

        public async Task DisconnectAsync()
        {
            await StopCaptureAsync();
            SetStatus(AnalyzerStatus.Disconnected, "Эмулятор отключён");
        }

        public Task StartCaptureAsync(CaptureSettings settings, CancellationToken cancellationToken = default)
        {
            if (_status != AnalyzerStatus.Ready && _status != AnalyzerStatus.Paused)
                throw new InvalidOperationException($"Нельзя начать захват в статусе {_status}.");

            ArgumentNullException.ThrowIfNull(settings);
            _paused = false;
            SetStatus(AnalyzerStatus.Capturing, "Захват запущен");

            _captureCts = CancellationTokenSource.CreateLinkedTokenSource(_cts.Token, cancellationToken);
            var token = _captureCts.Token;
            _captureLoop = Task.Run(() => CaptureLoopAsync(settings, token), token);
            return Task.CompletedTask;
        }

        public async Task StopCaptureAsync()
        {
            var loop = _captureLoop;
            var cts = _captureCts;
            _captureLoop = null;
            _captureCts = null;

            if (loop is not null)
            {
                // Останавливаем поток генерации через токен захвата.
                cts?.Cancel();
                try { await Task.WhenAny(loop, Task.Delay(TimeSpan.FromSeconds(2))); }
                catch (OperationCanceledException) { /* игнорируем */ }
                finally { cts?.Dispose(); }
            }

            if (_status is AnalyzerStatus.Capturing or AnalyzerStatus.Paused)
                SetStatus(AnalyzerStatus.Ready, "Захват остановлен");
        }

        public Task SetPausedAsync(bool paused)
        {
            _paused = paused;
            if (_status is AnalyzerStatus.Capturing or AnalyzerStatus.Paused)
                SetStatus(paused ? AnalyzerStatus.Paused : AnalyzerStatus.Capturing,
                          paused ? "Захват на паузе" : "Захват возобновлён");
            return Task.CompletedTask;
        }

        public async IAsyncEnumerable<UsbPacket> ReadPacketsAsync(
            [EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            // В эмуляторе пакеты отдаются только через событие PacketCaptured.
            // У реальной реализации здесь читается DMA/кольцевой буфер драйвера.
            await Task.CompletedTask;
            yield break;
        }

        public async Task ExportAsync(string filePath, CancellationToken cancellationToken = default)
        {
            // Заглушка: реальная реализация пишет .csv/.pcapng из хранилища.
            await File.WriteAllTextAsync(filePath,
                "seq,time_ns,type,direction,addr,ep,len,payload_hex\n", cancellationToken);
        }

        public void Dispose()
        {
            _cts.Cancel();
            _captureLoop?.Wait(TimeSpan.FromSeconds(1));
            _cts.Dispose();
        }

        // ---------- внутренняя логика эмуляции ----------

        private async Task CaptureLoopAsync(CaptureSettings settings, CancellationToken token)
        {
            var sw = System.Diagnostics.Stopwatch.StartNew();
            while (!token.IsCancellationRequested)
            {
                if (_paused)
                {
                    try { await Task.Delay(100, token); }
                    catch (OperationCanceledException) { break; }
                    continue;
                }

                var packet = GeneratePacket(sw.ElapsedTicks * 100); // ticks → ns примерно
                if (PassesFilters(packet, settings))
                    PacketCaptured?.Invoke(this, new PacketCapturedEventArgs(packet));

                try { await Task.Delay(_rng.Next(1, 40), token); }
                catch (OperationCanceledException) { break; }
            }
        }

        private UsbPacket GeneratePacket(long timestampNs)
        {
            TransactionType[] types = [TransactionType.Setup, TransactionType.In, TransactionType.Out, TransactionType.Acknowledge];
            var type = types[_rng.Next(types.Length)];
            int payloadLen = type switch
            {
                TransactionType.Setup => 8,
                TransactionType.In or TransactionType.Out => _rng.Next(0, 64),
                _ => 0
            };
            var payload = new byte[payloadLen];
            _rng.NextBytes(payload);

            var direction = type switch
            {
                TransactionType.Out => TransferDirection.HostToDevice,
                TransactionType.In => TransferDirection.DeviceToHost,
                TransactionType.Setup => TransferDirection.HostToDevice,
                _ => TransferDirection.Unknown
            };

            return new UsbPacket(
                sequenceNumber: Interlocked.Increment(ref _sequence),
                timestampNs: timestampNs,
                type: type,
                direction: direction,
                deviceAddress: (byte)_rng.Next(1, 128),
                endpointNumber: (byte)_rng.Next(0, 16),
                frameNumber: (ushort)(_rng.Next(0, 2048)),
                payload: payload,
                hasCrcError: _rng.NextDouble() < 0.01);
        }

        private static bool PassesFilters(in UsbPacket packet, CaptureSettings settings)
        {
            if (settings.Filters.Count == 0) return true;
            foreach (var filter in settings.Filters)
            {
                if (!filter.Matches(in packet)) return false;
            }
            return true;
        }

        private void SetStatus(AnalyzerStatus newState, string? message = null)
        {
            var old = _status;
            _status = newState;
            StatusChanged?.Invoke(this, new AnalyzerStatusChangedEventArgs(old, newState, message));
        }
    }
}
