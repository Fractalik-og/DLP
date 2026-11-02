using DLP.UsbController.Enums;
using DLP.UsbController.Models;

namespace DLP.UsbController.Interfaces
{
    /// <summary>
    /// Хранилище результатов захвата: кольцевой буфер, фильтрация, экспорт.
    /// Отделяет логику накопления данных от аппаратного сервиса.
    /// </summary>
    public interface ICaptureStore
    {
        /// <summary>Количество сохранённых пакетов.</summary>
        long Count { get; }

        /// <summary>Текущая статистика захвата.</summary>
        CaptureStatistics Statistics { get; }

        /// <summary>Добавить пакет (вызывается сервисом анализатора).</summary>
        void Add(in UsbPacket packet);

        /// <summary>Получить срез пакетов для отображения в UI (virtualized list).</summary>
        IReadOnlyList<UsbPacket> GetRange(long startIndex, int count);

        /// <summary>Пакеты, проходящие сквозь указанный фильтр.</summary>
        IEnumerable<UsbPacket> Query(CaptureFilter filter);

        /// <summary>Очистка буфера и статистики.</summary>
        void Clear();
    }
}
