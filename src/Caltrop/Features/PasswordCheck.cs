using System.Text;
using CaltropSecurity.Internal;

public static partial class Caltrop
{
    public static partial class Passwords
    {
        private static readonly Lazy<HashSet<string>> s_common = new(LoadCommonPasswords);

        /// <summary>
        /// Checks whether a new password is good enough, fully offline: long enough, not one of the 10,000 most common
        /// passwords (including look-alikes such as <c>P@ssw0rd!</c>), not built from the user's own name or email,
        /// and hard enough to guess. Uses the default rules (see <see cref="CaltropPasswordRules"/>).
        /// </summary>
        /// <param name="password">The new password.</param>
        /// <param name="relatedWords">Words the password must not contain: the user's name, email, your app's name.</param>
        /// <returns>The result, with a list of problems you can show to the user.</returns>
        /// <example>
        /// <code>
        /// var check = Caltrop.Passwords.Check(newPassword, user.Name, user.Email, "MyApp");
        /// if (!check.Ok) return string.Join(" ", check.Problems);
        /// </code>
        /// </example>
        public static CaltropPasswordCheck Check(string password, params string[] relatedWords) =>
            Check(password, CaltropPasswordRules.Default, relatedWords);

        /// <summary>Checks whether a new password is good enough, using your own rules.</summary>
        /// <param name="password">The new password.</param>
        /// <param name="rules">Your rules, for example <c>new CaltropPasswordRules { MinLength = 16 }</c>.</param>
        /// <param name="relatedWords">Words the password must not contain: the user's name, email, your app's name.</param>
        /// <returns>The result, with a list of problems you can show to the user.</returns>
        public static CaltropPasswordCheck Check(string password, CaltropPasswordRules rules, params string[] relatedWords)
        {
            ArgumentNullException.ThrowIfNull(password);
            ArgumentNullException.ThrowIfNull(rules);
            relatedWords ??= [];

            string normalized = SafeNormalize(password);
            var problems = new List<string>();
            if (!Encodings.IsValidUnicode(password))
            {
                problems.Add("The password contains a character that cannot be used. Type it again.");
            }
            int length = normalized.EnumerateRunes().Count();
            if (length < rules.MinLength)
            {
                problems.Add($"Use at least {rules.MinLength} characters.");
            }

            if (length > rules.MaxLength)
            {
                problems.Add($"Use at most {rules.MaxLength} characters.");
            }

            string lower = normalized.ToLowerInvariant();
            bool common = rules.BlockCommon && IsCommon(lower);
            if (common)
            {
                problems.Add("This is one of the most common passwords. Attackers try these first.");
            }

            bool related = ContainsRelatedWord(lower, relatedWords);
            if (related)
            {
                problems.Add("Don't use your name, your email address or the app's name in your password.");
            }

            double bits = EstimateBits(normalized);
            int score = bits switch
            {
                < 28 => 0,
                < 40 => 1,
                < 60 => 2,
                < 80 => 3,
                _ => 4,
            };

            if (common)
            {
                score = 0;
            }
            else if (related)
            {
                score = Math.Min(score, 1);
            }

            if (!common && score < rules.MinScore)
            {
                problems.Add(score <= 1
                    ? "This is too easy to guess. Use a longer password, such as a few random words."
                    : "This could be stronger. Add another word or a few more characters.");
            }

            return new CaltropPasswordCheck(problems.Count == 0, score, problems);
        }

        private static bool IsCommon(string lower)
        {
            HashSet<string> common = s_common.Value;
            foreach (string candidate in Variants(lower))
            {
                if (candidate.Length >= 4 && common.Contains(candidate))
                {
                    return true;
                }
            }

            return false;
        }

        /// <summary>The password, with look-alike characters swapped back, and with digits and symbols trimmed off the ends.</summary>
        private static IEnumerable<string> Variants(string lower)
        {
            string trimmed = lower.Trim("0123456789!@#$%^&*()_+-=.,?~ ".ToCharArray());
            foreach (string text in new[] { lower, trimmed })
            {
                yield return text;
                yield return Deleet(text, 'i');
                yield return Deleet(text, 'l');
                string deleeted = Deleet(text, 'i');
                yield return deleeted.Trim("0123456789!@#$%^&*()_+-=.,?~ ".ToCharArray());
            }
        }

        private static string Deleet(string text, char one)
        {
            var builder = new StringBuilder(text.Length);
            foreach (char c in text)
            {
                builder.Append(c switch
                {
                    '0' => 'o',
                    '1' => one,
                    '3' => 'e',
                    '4' or '@' => 'a',
                    '5' or '$' => 's',
                    '7' or '+' => 't',
                    '8' => 'b',
                    '9' => 'g',
                    '!' or '|' => 'i',
                    _ => c,
                });
            }

            return builder.ToString();
        }

        private static bool ContainsRelatedWord(string lower, string[] relatedWords)
        {
            string deleeted = Deleet(lower, 'i');
            foreach (string? word in relatedWords)
            {
                if (string.IsNullOrWhiteSpace(word))
                {
                    continue;
                }

                // Split "Alice Smith" or "alice.smith@example.com" into its parts.
                foreach (string part in SplitWords(word.ToLowerInvariant()))
                {
                    if (part.Length >= 3 && (lower.Contains(part, StringComparison.Ordinal) || deleeted.Contains(part, StringComparison.Ordinal)))
                    {
                        return true;
                    }
                }
            }

            return false;
        }

        private static IEnumerable<string> SplitWords(string text)
        {
            var current = new StringBuilder();
            foreach (char c in text)
            {
                if (char.IsLetterOrDigit(c))
                {
                    current.Append(c);
                }
                else if (current.Length > 0)
                {
                    yield return current.ToString();
                    current.Clear();
                }
            }

            if (current.Length > 0)
            {
                yield return current.ToString();
            }
        }

        /// <summary>
        /// A rough guess at how many bits of guessing it takes: characters from a bigger alphabet count for more, while
        /// repeats ("aaaa"), sequences ("abcd", "4321") and keyboard runs ("qwerty") count for almost nothing.
        /// </summary>
        private static double EstimateBits(string password)
        {
            int[] runes = [.. password.EnumerateRunes().Select(rune => rune.Value)];
            if (runes.Length == 0)
            {
                return 0;
            }

            // A password that is one short chunk repeated ("abcabcabc") is only as strong as the chunk.
            for (int unit = 1; unit <= runes.Length / 2; unit++)
            {
                if (runes.Length % unit == 0 && IsRepetition(runes, unit))
                {
                    return EstimateBits(string.Concat(password.EnumerateRunes().Take(unit).Select(rune => rune.ToString()))) + Math.Log2(runes.Length / unit);
                }
            }

            int alphabet = 0;
            alphabet += runes.Any(r => r is >= 'a' and <= 'z') ? 26 : 0;
            alphabet += runes.Any(r => r is >= 'A' and <= 'Z') ? 26 : 0;
            alphabet += runes.Any(r => r is >= '0' and <= '9') ? 10 : 0;
            alphabet += runes.Any(r => r is >= 0x20 and < 0x7F && !char.IsAsciiLetterOrDigit((char)r)) ? 33 : 0;
            alphabet += runes.Any(r => r >= 0x80) ? 100 : 0;
            double perCharacter = Math.Log2(Math.Max(alphabet, 2));

            bool[] weak = new bool[runes.Length];
            MarkRepeats(runes, weak);
            MarkSequences(runes, weak);
            MarkKeyboardRuns(password.ToLowerInvariant(), weak);

            double bits = 0;
            for (int i = 0; i < runes.Length; i++)
            {
                bits += weak[i] ? 1 : perCharacter;
            }

            return bits;
        }

        private static bool IsRepetition(int[] runes, int unit)
        {
            for (int i = unit; i < runes.Length; i++)
            {
                if (runes[i] != runes[i % unit])
                {
                    return false;
                }
            }

            return true;
        }

        private static void MarkRepeats(int[] runes, bool[] weak)
        {
            for (int i = 2; i < runes.Length; i++)
            {
                if (runes[i] == runes[i - 1] && runes[i - 1] == runes[i - 2])
                {
                    weak[i] = weak[i - 1] = true;
                }
            }
        }

        private static void MarkSequences(int[] runes, bool[] weak)
        {
            for (int i = 2; i < runes.Length; i++)
            {
                int step = runes[i] - runes[i - 1];
                if (step is 1 or -1 && runes[i - 1] - runes[i - 2] == step && char.IsAsciiLetterOrDigit((char)runes[i]))
                {
                    weak[i] = weak[i - 1] = true;
                }
            }
        }

        private static void MarkKeyboardRuns(string lower, bool[] weak)
        {
            string[] rows = ["1234567890", "qwertyuiop", "asdfghjkl", "zxcvbnm", "qazwsxedc"];
            if (lower.Length != weak.Length)
            {
                return; // non-BMP characters: skip this refinement
            }

            for (int i = 2; i < lower.Length; i++)
            {
                foreach (string row in rows)
                {
                    int a = row.IndexOf(lower[i - 2], StringComparison.Ordinal);
                    int b = row.IndexOf(lower[i - 1], StringComparison.Ordinal);
                    int c = row.IndexOf(lower[i], StringComparison.Ordinal);
                    if (a >= 0 && b >= 0 && c >= 0 && b - a == c - b && Math.Abs(c - b) == 1)
                    {
                        weak[i] = weak[i - 1] = true;
                    }
                }
            }
        }

        private static string SafeNormalize(string text)
        {
            try
            {
                return text.IsNormalized(NormalizationForm.FormC) ? text : text.Normalize(NormalizationForm.FormC);
            }
            catch (ArgumentException)
            {
                return text;
            }
        }

        private static HashSet<string> LoadCommonPasswords()
        {
            using Stream? stream = typeof(Caltrop).Assembly.GetManifestResourceStream("Caltrop.common-passwords.txt");
            var set = new HashSet<string>(StringComparer.Ordinal);
            if (stream is null)
            {
                return set;
            }

            using var reader = new StreamReader(stream, Encoding.UTF8);
            while (reader.ReadLine() is { } line)
            {
                if (line.Length > 0)
                {
                    set.Add(line);
                }
            }

            return set;
        }
    }
}

/// <summary>Your rules for <see cref="Caltrop.Passwords.Check(string, CaltropPasswordRules, string[])"/>.</summary>
/// <example><code>var rules = new CaltropPasswordRules { MinLength = 16, MinScore = 4 };</code></example>
public sealed class CaltropPasswordRules
{
    private readonly int _minLength = 12;
    private readonly int _maxLength = 128;
    private readonly int _minScore = 3;

    /// <summary>The default rules: at least 12 characters, at most 128, not common, score at least 3.</summary>
    public static CaltropPasswordRules Default { get; } = new();

    /// <summary>The fewest characters allowed. Default 12.</summary>
    public int MinLength
    {
        get => _minLength;
        init
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(value, 1);
            _minLength = value;
        }
    }

    /// <summary>The most characters allowed. Default 128.</summary>
    public int MaxLength
    {
        get => _maxLength;
        init
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(value, 1);
            _maxLength = value;
        }
    }

    /// <summary>Whether to reject the 10,000 most common passwords and their look-alikes. Default <see langword="true"/>.</summary>
    public bool BlockCommon { get; init; } = true;

    /// <summary>The lowest acceptable score, from 0 (allow anything) to 4 (very strong only). Default 3.</summary>
    public int MinScore
    {
        get => _minScore;
        init
        {
            ArgumentOutOfRangeException.ThrowIfNegative(value);
            ArgumentOutOfRangeException.ThrowIfGreaterThan(value, 4);
            _minScore = value;
        }
    }
}

/// <summary>The result of <see cref="Caltrop.Passwords.Check(string, string[])"/>.</summary>
public sealed class CaltropPasswordCheck
{
    private static readonly string[] s_names = ["Very weak", "Weak", "Fair", "Strong", "Very strong"];

    internal CaltropPasswordCheck(bool isOk, int score, IReadOnlyList<string> problems)
    {
        Ok = isOk;
        Score = score;
        Problems = problems;
    }

    /// <summary><see langword="true"/> if the password follows every rule.</summary>
    public bool Ok { get; }

    /// <summary>How hard it is to guess, from 0 (very weak) to 4 (very strong). An estimate.</summary>
    public int Score { get; }

    /// <summary>The score in words: "Very weak", "Weak", "Fair", "Strong" or "Very strong".</summary>
    public string Strength => s_names[Score];

    /// <summary>What is wrong, as sentences you can show to the user. Empty if <see cref="Ok"/>.</summary>
    public IReadOnlyList<string> Problems { get; }

    /// <summary>Returns the strength and any problems.</summary>
    public override string ToString() => Ok ? Strength : $"{Strength}: {string.Join(" ", Problems)}";
}
