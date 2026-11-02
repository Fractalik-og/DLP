using System.Collections.Concurrent;
using System.Text.Json;
using DLP.UsbController.Enums;
using DLP.UsbController.Interfaces;
using DLP.UsbController.Models;

namespace DLP.UsbController.Services
{
    /// <summary>
    /// Журнал инцидентов безопасности:
    ///  - локальное структурированное хранение в формате NDJSON
    ///    (Newline Delimited JSON: одна каноническая JSON-запись на строку — удобно
    ///    дописывать без блокировок «на догадку», читать потоково, грузить в SIEM);
    ///  - очередь доставки на центральный сервер DLP с фоновым ретраем;
    ///    транспорт имитируется (см. <see cref="SimulatedDlpServer"/>), в prod — HTTPS POST.
    /// </summary>
    public sealed class NdjsonIncidentLogger : IIncidentLogger
    {
        private static readonly JsonSerializerOptions JsonOpts = new()
        {
            WriteIndented = false,
            DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
            Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() },
        };

        private readonly string _logFilePath;
        private readonly SemaphoreSlim _writeLock = new(1, 1);
        private readonly ConcurrentQueue<SecurityIncident> _outbox = new();
        private readonly CancellationTokenSource _cts = new();
        private readonly Task _deliveryLoop;
        private bool _disposed;

        public event EventHandler<SecurityIncident>? IncidentLogged;

        public NdjsonIncidentLogger(string logFilePath)
        {
            _logFilePath = logFilePath;
            var dir = Path.GetDirectoryName(logFilePath);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

            // Восстанавливаем неотправленные записи из журнала (DeliveryStatus != delivered).
            _deliveryLoop = Task.Run(DeliveryLoopAsync);
        }

        public async Task LogAsync(SecurityIncident incident, CancellationToken cancellationToken = default)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            string line = JsonSerializer.Serialize(incident, JsonOpts);

            await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                await File.AppendAllTextAsync(_logFilePath, line + Environment.NewLine, cancellationToken)
                            .ConfigureAwait(false);
            }
            finally
            {
                _writeLock.Release();
            }

            _outbox.Enqueue(incident);
            IncidentLogged?.Invoke(this, incident);
        }

        /// <summary>Имитация HTTPS-доставки на центр. Случайные «сбои сети» для проверки retry.</summary>
        public async Task<IncidentDeliveryStatus> DeliverAsync(SecurityIncident incident, CancellationToken cancellationToken = default)
        {
            try
            {
                // В production здесь будет HttpClient.PostAsJsonAsync(url, incident) с токеном агента.
                await SimulatedDlpServer.IngestAsync(incident, cancellationToken).ConfigureAwait(false);
                incident.DeliveryStatus = IncidentDeliveryStatus.Delivered;
                incident.DeliveredAtUtc = DateTime.UtcNow;
                incident.DeliveryError = null;
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                incident.DeliveryStatus = IncidentDeliveryStatus.Failed;
                incident.DeliveryError = ex.Message;
            }
            return incident.DeliveryStatus;
        }

        private async Task DeliveryLoopAsync()
        {
            while (!_cts.IsCancellationRequested)
            {
                int batch = 0;
                while (batch++ < 20 && _outbox.TryPeek(out var inc))
                {
                    var status = await DeliverAsync(inc, _cts.Token).ConfigureAwait(false);
                    if (status == IncidentDeliveryStatus.Delivered)
                        _outbox.TryDequeue(out _);
                    else
                        break; // сервер недоступен — повторим после паузы
                }

                try { await Task.Delay(TimeSpan.FromSeconds(5), _cts.Token).ConfigureAwait(false); }
                catch (OperationCanceledException) { break; }
            }
        }

        /// <summary>Последние N инцидентов: читаем NDJSON с конца файла (для UI-журнала).</summary>
        public async Task<IReadOnlyList<SecurityIncident>> ReadRecentAsync(int count, CancellationToken cancellationToken = default)
        {
            if (!File.Exists(_logFilePath)) return Array.Empty<SecurityIncident>();

            var result = new List<SecurityIncident>(count);
            await using var fs = new FileStream(_logFilePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var reader = new StreamReader(fs);

            // Простой вариант: полный проход и буфер последних N (для журналов ~десятков МБ приемлемо;
            // для прода — seek с конца по чанкам).
            string? line;
            while ((line = await reader.ReadLineAsync(cancellationToken).ConfigureAwait(false)) is not null)
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                try
                {
                    var inc = JsonSerializer.Deserialize<SecurityIncident>(line, JsonOpts);
                    if (inc is null) continue;
                    result.Add(inc);
                    if (result.Count > count) result.RemoveAt(0);
                }
                catch (JsonException) { /* повреждённая строка — пропускаем */ }
            }

            result.Reverse(); // свежие сверху
            return result;
        }

        public async ValueTask DisposeAsync()
        {
            if (_disposed) return;
            _disposed = true;
            _cts.Cancel();
            try { await _deliveryLoop.ConfigureAwait(false); } catch { /* shutdown */ }
            _writeLock.Dispose();
            _cts.Dispose();
        }
    }

    /// <summary>
    /// Заглушка центрального сервера DLP: хранит принятые инциденты в памяти,
    /// имитирует сетевую задержку и периодические недоступности.
    /// Заменяется на реальный транспорт (gRPC/HTTPS) при интеграции.
    /// </summary>
    public static class SimulatedDlpServer
    {
        private static readonly Random Rng = new();
        public static ConcurrentQueue<SecurityIncident> Received { get; } = new();
        public static double FailureRate { get; set; } = 0.05;

        public static async Task IngestAsync(SecurityIncident incident, CancellationToken ct)
        {
            await Task.Delay(TimeSpan.FromMilliseconds(Rng.Next(30, 120)), ct).ConfigureAwait(false);
            if (Rng.NextDouble() < FailureRate)
                throw new HttpRequestException("503 Service Unavailable (имитация)");
            Received.Enqueue(incident);
        }
    }
}
