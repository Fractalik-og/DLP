using System.ComponentModel;
using System.Reflection;

namespace DLP.UsbController.Enums
{
    /// <summary>
    /// Русский текст перечислений для интерфейса: берётся из атрибута [Description],
    /// а если его нет — имя члена enum как есть.
    /// </summary>
    public static class EnumDisplayRu
    {
        public static string Text(this Enum? value)
        {
            if (value is null) return "";
            var name = value.ToString();
            var field = value.GetType().GetField(name);
            var desc = field?.GetCustomAttribute<DescriptionAttribute>()?.Description;
            return string.IsNullOrWhiteSpace(desc) ? name : desc;
        }
    }
}
