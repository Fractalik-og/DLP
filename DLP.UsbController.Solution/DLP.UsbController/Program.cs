using System.Text.Json;
using DLP.UsbController.Models;
using DLP.UsbController.Services;

namespace DLP.UsbController
{
    internal static class Program
    {
        /// <summary>
        /// Точка входа. На Windows запускается полноценный агент (WMI + реестр);
        /// в средах без WMI включается демонстрационный режим с эмуляцией носителя,
        /// чтобы конвейер «обнаружение → скан → принуждение → NDJSON → центр» был проверяем.
        /// </summary>
        [STAThread]
        static void Main()
        {
            ApplicationConfiguration.Initialize();

            string dataDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "DlpAgent");
            if (!OperatingSystem.IsWindows())
                dataDir = Path.Combine(Path.GetTempPath(), "DlpAgent");
            Directory.CreateDirectory(dataDir);

            var policy = LoadOrCreatePolicy(Path.Combine(dataDir, "policy.json"));

            var logger = CreateLogger(policy, dataDir);
            try
            {
                var form = AgentForm.CreateForDemo(policy, logger);
                Application.Run(form);
            }
            finally
            {
                // Синхронный Main не позволяет await using — закрываем логгер «огонь и завершение».
                logger.DisposeAsync().AsTask().GetAwaiter().GetResult();
            }
        }

        private static NdjsonIncidentLogger CreateLogger(DlpPolicyConfig policy, string dataDir)
        {
            string logPath = policy.IncidentLogPath.StartsWith(@"C:\") || !OperatingSystem.IsWindows()
                ? Path.Combine(dataDir, "incidents.ndjson")
                : policy.IncidentLogPath;
            return new NdjsonIncidentLogger(logPath);
        }

        private static DlpPolicyConfig LoadOrCreatePolicy(string path)
        {
            var opts = new JsonSerializerOptions
            {
                WriteIndented = true,
                Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() },
            };

            try
            {
                if (File.Exists(path))
                {
                    var loaded = JsonSerializer.Deserialize<DlpPolicyConfig>(File.ReadAllText(path), opts);
                    if (loaded is not null) return loaded;
                }
            }
            catch (JsonException) { /* повреждённый файл — пересоздаём дефолтный */ }

            var fresh = new DlpPolicyConfig();
            try { File.WriteAllText(path, JsonSerializer.Serialize(fresh, opts)); }
            catch (IOException) { /* права на каталог — работаем с политикой в памяти */ }
            return fresh;
        }
    }
}
