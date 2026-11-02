using System.IO;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Channels;
using DLP.UsbController.Enums;
using DLP.UsbController.Interfaces;
using DLP.UsbController.Models;

namespace DLP.UsbController.Services
{
    /// <summary>
    /// Статический анализатор файлового содержимого съёмного носителя.
    /// Комбинация двух методов детектирования:
    ///  - регулярные выражения для структурированных реквизитов
    ///    (СНИЛС с контрольной суммой, ИНН 10/12 цифр, номер банковской карты по алгоритму Луна,
    ///     номер паспорта серии/номера РФ);
    ///  - словари ключевых слов для грифов секретности и прочей лексики политики.
    /// Найденные фрагменты маскируются до записи в журнал (принцип минимизации ПДн).
    /// </summary>
    public sealed partial class ContentScanner : IContentScanner
    {
        private readonly DlpPolicyConfig _policy;
        private static readonly Regex SnilsRegex = Snils();
        private static readonly Regex DigitRuns = DigitRunRegex();
        private static readonly Regex PassportRegex = RuPassport();

        public IReadOnlyList<ScanRule> Rules { get; }

        public ContentScanner(DlpPolicyConfig policy)
        {
            _policy = policy;

            var rules = new List<ScanRule>
            {
                new("SNILS (контрольная сумма)", FindingCategory.PersonalData, IncidentSeverity.High, RuleKind.Regex, "snils"),
                new("INN 10/12 цифр", FindingCategory.PersonalData, IncidentSeverity.Medium, RuleKind.Regex, "inn"),
                new("Bank card (LUHN)", FindingCategory.Financial, IncidentSeverity.High, RuleKind.Regex, "card"),
                new("Паспорт РФ серия/номер", FindingCategory.PersonalData, IncidentSeverity.High, RuleKind.Regex, "passport"),
            };
            foreach (var (cat, words) in policy.KeywordDictionaries)
                foreach (var w in words)
                    rules.Add(new ScanRule($"Словарь[{cat}]: {w}", cat,
                        cat == FindingCategory.ClassifiedMarking ? IncidentSeverity.Critical : IncidentSeverity.Medium,
                        RuleKind.KeywordDictionary, w));
            Rules = rules;
        }

        [GeneratedRegex(@"\b\d{3}[-\s]?\d{3}[-\s]?\d{3}[-\s]?\d{2}\b")]
        private static partial Regex Snils();

        /// <summary>Слитные последовательности цифр (карты/счета/ИНН и т.п.).</summary>
        [GeneratedRegex(@"\d+")]
        private static partial Regex DigitRunRegex();

        [GeneratedRegex(@"\b[45]\d{2}\s?\d{6}\b")]
        private static partial Regex RuPassport();

        public async Task<FileScanResult> ScanFileAsync(string fullPath, string relativePath, CancellationToken cancellationToken = default)
        {
            var fi = new FileInfo(fullPath);
            var result = new FileScanResult { RelativePath = relativePath, SizeBytes = fi.Exists ? fi.Length : 0 };

            if (!fi.Exists) { result.SkipReason = "missing"; return result; }
            if (fi.Extension.ToLowerInvariant() is not string ext || !_policy.TextFileExtensions.Contains(ext))
            { result.SkipReason = "unsupported-extension"; return result; }
            if (fi.Length > (long)_policy.MaxFileScanSizeMb * 1024 * 1024)
            { result.SkipReason = "too-large"; return result; }

            // Для Office/PDF — быстрый «грубый» поиск по сырым байтам (без парсеров формата):
            // извлекаем печатаемые последовательности и гоняем по ним правила.
            string text;
            try
            {
                text = await File.ReadAllTextAsync(fullPath, Encoding.UTF8, cancellationToken).ConfigureAwait(false);
            }
            catch (IOException)
            {
                byte[] raw;
                try { raw = await File.ReadAllBytesAsync(fullPath, cancellationToken).ConfigureAwait(false); }
                catch { result.SkipReason = "unreadable"; return result; }
                text = ExtractPrintable(raw);
            }
            catch (OperationCanceledException) { throw; }

            int lineNo = 0;
            foreach (var line in text.Split('\n'))
            {
                cancellationToken.ThrowIfCancellationRequested();
                lineNo++;
                ScanLine(line, relativePath, lineNo, result.Findings);
            }

            return result;
        }

        private void ScanLine(string line, string relPath, int lineNo, List<ContentFinding> sink)
        {
            // 1. Регулярные выражения со структурной валидацией.
            foreach (Match m in SnilsRegex.Matches(line))
                if (ValidateSnils(m.Value.Replace("-", "").Replace(" ", "")))
                    sink.Add(Find(FindingCategory.PersonalData, "SNILS", relPath, lineNo, Mask(m.Value), IncidentSeverity.High));

            foreach (Match m in DigitRunRegex().Matches(line))
            {
                var digits = m.Value;
                // Номер банковской карты: 13–19 цифр, проходит алгоритм Луна.
                if (digits.Length is >= 13 and <= 19 && IsValidLuhn(digits))
                    sink.Add(Find(FindingCategory.Financial, "BankCard/LUHN", relPath, lineNo, MaskCard(digits), IncidentSeverity.High));
                else if (digits.Length == 10 || digits.Length == 12)
                    sink.Add(Find(FindingCategory.PersonalData, "INN", relPath, lineNo, Mask(digits), IncidentSeverity.Medium));
            }

            foreach (Match m in PassportRegex.Matches(line))
                sink.Add(Find(FindingCategory.PersonalData, "RuPassport", relPath, lineNo, Mask(m.Value), IncidentSeverity.High));

            // 2. Словари ключевых слов.
            foreach (var (cat, words) in _policy.KeywordDictionaries)
                foreach (var w in words)
                {
                    int idx = line.IndexOf(w, StringComparison.OrdinalIgnoreCase);
                    if (idx >= 0)
                        sink.Add(Find(cat, $"dict:{w}", relPath, lineNo, w,
                            cat == FindingCategory.ClassifiedMarking ? IncidentSeverity.Critical : IncidentSeverity.Medium));
                }
        }

        private static ContentFinding Find(FindingCategory cat, string rule, string rel, int line, string masked, IncidentSeverity sev) =>
            new() { Category = cat, RuleName = rule, RelativePath = rel, LineNumber = line, MaskedMatch = masked, Severity = sev };

        /// <summary>Контрольная сумма СНИЛС: взвешенная сумма первых 9 цифр (веса 9..1) mod 101.</summary>
        internal static bool ValidateSnils(string digits11)
        {
            if (digits11.Length != 11 || !digits11.All(char.IsDigit)) return false;
            int sum = 0;
            for (int i = 0; i < 9; i++)
                sum += (digits11[i] - '0') * (9 - i);
            int control = sum % 101;
            if (control is 100 or 101) control = 0;
            int actual = int.Parse(digits11[9..]);
            return control == actual;
        }

        internal static bool IsValidLuhn(string digits)
        {
            if (digits.Length is < 13 or > 19 || !digits.All(char.IsDigit)) return false;
            int sum = 0;
            bool alt = false;
            for (int i = digits.Length - 1; i >= 0; i--)
            {
                int n = digits[i] - '0';
                if (alt) { n *= 2; if (n > 9) n -= 9; }
                sum += n;
                alt = !alt;
            }
            return sum % 10 == 0;
        }

        private static string Mask(string s) =>
            s.Length <= 4 ? new string('*', s.Length)
                          : s[..2] + new string('*', Math.Max(2, s.Length - 4)) + s[^2..];

        private static string MaskCard(string s)
        {
            var d = new string(s.Where(char.IsDigit).ToArray());
            return d.Length < 8 ? Mask(d) : $"{d[..4]} **** **** {d[^4..]}";
        }

        private static string ExtractPrintable(byte[] raw)
        {
            var sb = new StringBuilder(raw.Length / 2);
            foreach (var b in raw)
                if (b is >= 0x20 and < 0x7F or >= 0xC0) sb.Append((char)b);
                else if (b is (byte)'\n' or (byte)'\r' or (byte)'\t') sb.Append(' ');
                else sb.Append('·');
            return sb.ToString();
        }

        /// <summary>
        /// Рекурсивное сканирование тома producer/consumer-каналоми: обход дерева каталогов
        /// отделён от IO-ёмкого анализа файлов, параллелим чтение ограниченным числом задач.
        /// </summary>
        public async IAsyncEnumerable<FileScanResult> ScanVolumeAsync(
            RemovableVolumeInfo volume,
            IProgress<ScanProgress>? progress = null,
            [EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            var root = volume.DriveLetter.EndsWith(':') ? volume.DriveLetter + "\\" : volume.DriveLetter;
            var channel = Channel.CreateBounded<FileScanResult>(new BoundedChannelOptions(256)
            {
                FullMode = BoundedChannelFullMode.Wait,
                SingleReader = true,
                SingleWriter = true,
            });

            var produceTask = Task.Run(() => ProduceAsync(root, channel.Writer, cancellationToken), cancellationToken);

            int scanned = 0, skipped = 0, findings = 0;
            await foreach (var res in channel.Reader.ReadAllAsync(cancellationToken).ConfigureAwait(false))
            {
                if (res.SkipReason is not null) skipped++; else scanned++;
                findings += res.Findings.Count;
                progress?.Report(new ScanProgress(scanned, skipped, findings, res.RelativePath));
                yield return res;
            }

            await produceTask.ConfigureAwait(false);
        }

        private async Task ProduceAsync(string root, ChannelWriter<FileScanResult> writer, CancellationToken ct)
        {
            try
            {
                int fileCount = 0;
                var stack = new Stack<string>();
                stack.Push(root);

                while (stack.Count > 0 && !ct.IsCancellationRequested)
                {
                    var dir = stack.Pop();
                    IEnumerable<string> subdirs = [], files = [];
                    try
                    {
                        subdirs = Directory.EnumerateDirectories(dir);
                        files = Directory.EnumerateFiles(dir);
                    }
                    catch (UnauthorizedAccessException) { continue; }
                    catch (DirectoryNotFoundException) { continue; }

                    foreach (var sd in subdirs)
                        if (GetDepth(sd, root) <= _policy.MaxDirectoryDepth) stack.Push(sd);

                    foreach (var f in files)
                    {
                        if (++fileCount > _policy.MaxFilesPerVolume) { writer.TryComplete(); return; }
                        var rel = Path.GetRelativePath(root, f);
                        var res = await ScanFileAsync(f, rel, ct).ConfigureAwait(false);
                        await writer.WriteAsync(res, ct).ConfigureAwait(false);
                    }
                }
            }
            finally
            {
                writer.TryComplete();
            }
        }

        private static int GetDepth(string path, string root)
        {
            int depth = 0;
            var cur = path;
            while (cur is not null && !cur.Equals(root, StringComparison.OrdinalIgnoreCase))
            {
                cur = Path.GetDirectoryName(cur);
                depth++;
                if (depth > 64) break;
            }
            return depth;
        }
    }
}
