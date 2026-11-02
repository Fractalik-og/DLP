using System.IO;
using DLP.UsbController.Enums;
using DLP.UsbController.Interfaces;
using DLP.UsbController.Models;

namespace DLP.UsbController.Services
{
    /// <summary>
    /// Демонстрационный наблюдатель для сред без WMI/реального железа (Linux CI, песочница):
    /// эмулирует подключение «флешки» с тестовым деревом файлов, содержащим ПДн и грифы,
    /// порождая события DeviceArrived/DeviceRemoved с той же семантикой, что и WMI-версия.
    /// </summary>
    public sealed class SimulatedRemovableDeviceWatcher : IRemovableDeviceWatcher
    {
        private CancellationTokenSource? _cts;
        private Task? _loop;
        private readonly string _fakeRoot;
        private bool _running;

        public event EventHandler<RemovableDeviceEventArgs>? DeviceArrived;
        public event EventHandler<RemovableDeviceEventArgs>? DeviceRemoved;
        public TimeSpan PollingInterval { get; set; } = TimeSpan.FromSeconds(10);

        /// <param name="fakeRoot">Каталог, играющий роль тома съёмного носителя.</param>
        public SimulatedRemovableDeviceWatcher(string fakeRoot)
        {
            _fakeRoot = Path.GetFullPath(fakeRoot);
        }

        public void Start()
        {
            if (_running) return;
            _running = true;
            _cts = new CancellationTokenSource();
            var token = _cts.Token;
            _loop = Task.Run(() => RunAsync(token), token);
        }

        public async Task StopAsync()
        {
            _cts?.Cancel();
            if (_loop is not null)
            {
                try { await _loop.ConfigureAwait(false); }
                catch (OperationCanceledException) { }
            }
            _running = false;
        }

        private async Task RunAsync(CancellationToken ct)
        {
            SeedFakeVolume(_fakeRoot);

            var volume = new RemovableVolumeInfo
            {
                DeviceId = new UsbDeviceId(0x0951, 0x1666),   // Kingston DataTraveler
                SerialNumber = "KNEAD1234567",
                DriveLetter = _fakeRoot,                       // в демо «буква тома» = путь
                VolumeLabel = "DEMO_FLASH",
                FileSystem = "exFAT",
                TotalBytes = 32L * 1024 * 1024 * 1024,
                FreeBytes = 20L * 1024 * 1024 * 1024,
                DeviceType = RemovableDeviceType.UsbFlashDrive,
            };

            var device = new UsbDeviceInfo
            {
                DeviceId = volume.DeviceId,
                SerialNumber = volume.SerialNumber,
                Manufacturer = "Kingston",
                ProductName = "DataTraveler 3.0",
                DeviceClass = UsbDeviceClass.MassStorage,
                Speed = UsbSpeed.HighSpeed,
            };

            await Task.Delay(1500, ct).ConfigureAwait(false);           // «воткнули флешку»
            DeviceArrived?.Invoke(this, new RemovableDeviceEventArgs(device, [volume], true));

            // Через минуту — извлечение.
            await Task.Delay(TimeSpan.FromMinutes(1), ct).ConfigureAwait(false);
            DeviceRemoved?.Invoke(this, new RemovableDeviceEventArgs(device, [volume], false));
        }

        public Task<IReadOnlyList<RemovableVolumeInfo>> GetRemovableVolumesAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<RemovableVolumeInfo>>([]);

        /// <summary>Создаёт дерево «файлы на флешке», заведомо содержащие конфиденциальные фрагменты.</summary>
        private static void SeedFakeVolume(string root)
        {
            Directory.CreateDirectory(Path.Combine(root, "Документы"));
            Directory.CreateDirectory(Path.Combine(root, "Бухгалтерия"));

            File.WriteAllText(Path.Combine(root, "readme.txt"),
                "Содержимое служебное. Для вопросов обращаться к администратору.");

            File.WriteAllText(Path.Combine(root, "Документы", "сотрудники.csv"),
                "ФИО;Дата рождения;СНИЛС;ИНН\n" +
                "Иванов И.И.;1985-04-12;112-233-445 95;7715123456\n" +
                "Петрова А.С.;1990-11-02;135-000-000 01;502711122233\n");

            File.WriteAllText(Path.Combine(root, "Документы", "объяснительная.txt"),
                "Я, Иванов Иван Иванович, паспорт 45 12 345678, выдан ОВД р-на..., " +
                "прошу предоставить отпуск. Персональные данные прошу не разглашать.\n");

            File.WriteAllText(Path.Combine(root, "Бухгалтерия", "платежки.log"),
                "Платёжное поручение №145 от 12.03: карта 4081 7810 4456 7892, " +
                "расчётный счёт 40703810000000123450, реквизиты получателя приложены.\n");

            File.WriteAllText(Path.Combine(root, "Бухгалтерия", "акт_секретно.txt"),
                "СЕКРЕТНО\nЭкземпляр №1\nКоммерческая тайна: гриф «Для служебного пользования».\n" +
                "Проект «Молния» — совершенно секретно.\n");
        }

        public async ValueTask DisposeAsync()
        {
            await StopAsync().ConfigureAwait(false);
            _cts?.Dispose();
        }
    }
}
