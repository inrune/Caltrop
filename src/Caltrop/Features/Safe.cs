using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using CaltropSecurity.Internal;

public static partial class Caltrop
{
    /// <summary>
    /// Helpers for input that comes from outside your app (users, uploads, requests, files): keep paths inside their
    /// folder, make file names safe, show text in HTML safely, hide secrets in logs, and strip invisible characters.
    /// </summary>
    /// <example>
    /// <code>
    /// string file  = Caltrop.Safe.PathInside("uploads", request.FileName);   // throws on "../../secret.txt"
    /// string name  = Caltrop.Safe.FileName(upload.Name);                       // "invoice.pdf", never "..\x.exe"
    /// string html  = $"&lt;p&gt;Hello {Caltrop.Safe.Html(user.Name)}&lt;/p&gt;";  // no script injection
    /// logger.LogInformation(Caltrop.Safe.Mask(requestBody));                  // cards, emails, passwords hidden
    /// </code>
    /// </example>
    public static partial class Safe
    {
        private const string Hidden = "****";

        private static readonly string[] s_reservedWindowsNames =
        [
            "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$",
            "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "COM¹", "COM²", "COM³",
            "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9", "LPT¹", "LPT²", "LPT³",
        ];

        /// <summary>
        /// Turns an untrusted relative path (such as a file name from a request) into a full path that is guaranteed
        /// to be inside <paramref name="folder"/>. Blocks <c>..</c> tricks, absolute paths, drive letters, network
        /// paths, Windows device names and symbolic links that point outside the folder.
        /// </summary>
        /// <param name="folder">The folder everything must stay inside.</param>
        /// <param name="untrustedPath">The relative path from outside, for example <c>"photos/cat.jpg"</c>.</param>
        /// <returns>The full path inside <paramref name="folder"/>.</returns>
        /// <exception cref="CaltropException">The path would leave the folder (<see cref="CaltropErrorCode.UnsafeInput"/>).</exception>
        public static string PathInside(string folder, string untrustedPath)
        {
            ArgumentException.ThrowIfNullOrEmpty(folder);
            ArgumentNullException.ThrowIfNull(untrustedPath);
            if (untrustedPath.Length == 0 || untrustedPath.Contains('\0', StringComparison.Ordinal))
            {
                throw Unsafe("The path is empty or contains a null character.");
            }

            if (Path.IsPathRooted(untrustedPath) || untrustedPath.StartsWith('/') || untrustedPath.StartsWith('\\')
                || (untrustedPath.Length >= 2 && char.IsAsciiLetter(untrustedPath[0]) && untrustedPath[1] == ':'))
            {
                throw Unsafe("The path must be relative: it cannot start with a drive, a slash or a network share.");
            }

            if (OperatingSystem.IsWindows() && untrustedPath.Contains(':', StringComparison.Ordinal))
            {
                throw Unsafe("The path contains ':', which Windows uses for drives and hidden data streams.");
            }

            string[] segments = untrustedPath.Split(['/', '\\'], StringSplitOptions.RemoveEmptyEntries);
            foreach (string segment in segments)
            {
                if (IsReservedWindowsName(segment))
                {
                    throw Unsafe($"\"{segment}\" is a reserved device name on Windows.");
                }
            }

            string root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(folder)) + Path.DirectorySeparatorChar;
            string full = Path.GetFullPath(Path.Combine(root, untrustedPath));
            if (!IsUnder(full, root))
            {
                throw Unsafe("The path leads outside its folder.");
            }

            // A symbolic link inside the folder could still point outside it: check every part that exists.
            string current = root;
            foreach (string part in Path.GetRelativePath(root, full).Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries))
            {
                current = Path.Combine(current, part);
                FileSystemInfo info = Directory.Exists(current) ? new DirectoryInfo(current) : new FileInfo(current);
                if (!info.Exists)
                {
                    break;
                }

                if (info.LinkTarget is not null)
                {
                    FileSystemInfo? target = info.ResolveLinkTarget(returnFinalTarget: true);
                    if (target is null || !IsUnder(Path.GetFullPath(target.FullName), root))
                    {
                        throw Unsafe("The path goes through a link that points outside its folder.");
                    }
                }
            }

            return full;
        }

        /// <summary>
        /// Makes an untrusted file name (for example from an upload) safe to save: keeps only the last part of any
        /// path, removes characters that are not allowed or are invisible, and avoids hidden and reserved names.
        /// </summary>
        /// <param name="untrustedName">The file name from outside.</param>
        /// <param name="fallback">What to use if nothing usable is left. Default <c>"file"</c>.</param>
        /// <returns>A plain file name with no folders, at most 200 characters, keeping the extension where possible.</returns>
        public static string FileName(string? untrustedName, string fallback = "file")
        {
            ArgumentException.ThrowIfNullOrEmpty(fallback);
            string name = CleanText(untrustedName ?? string.Empty);
            int slash = name.LastIndexOfAny(['/', '\\']);
            name = name[(slash + 1)..];

            var builder = new StringBuilder(name.Length);
            foreach (char c in name)
            {
                builder.Append(char.IsControl(c) || c is '<' or '>' or ':' or '"' or '|' or '?' or '*' ? '_' : c);
            }

            name = builder.ToString().Trim().TrimEnd('.', ' ').TrimStart('.');
            if (name.Length > 200)
            {
                string extension = Path.GetExtension(name);
                extension = extension.Length is > 1 and <= 16 ? extension : string.Empty;
                name = name[..(200 - extension.Length)].TrimEnd('.', ' ') + extension;
            }

            if (name.Length == 0)
            {
                return fallback;
            }

            return IsReservedWindowsName(name) ? "_" + name : name;
        }

        /// <summary>
        /// Encodes text so it shows as plain text inside HTML, including inside quoted attributes. Use it for anything
        /// from users that you put into a page, so it can never become a script or tag.
        /// </summary>
        /// <param name="text">The text. <see langword="null"/> gives an empty string.</param>
        /// <returns>HTML-encoded text.</returns>
        public static string Html(string? text)
        {
            if (string.IsNullOrEmpty(text))
            {
                return string.Empty;
            }

            var builder = new StringBuilder(text.Length + 16);
            foreach (Rune rune in text.EnumerateRunes())
            {
                switch (rune.Value)
                {
                    case '&': builder.Append("&amp;"); break;
                    case '<': builder.Append("&lt;"); break;
                    case '>': builder.Append("&gt;"); break;
                    case '"': builder.Append("&quot;"); break;
                    case '\'': builder.Append("&#39;"); break;
                    case '`': builder.Append("&#96;"); break;
                    case '\t' or '\n' or '\r': builder.Append((char)rune.Value); break;
                    case < 0x20 or (>= 0x7F and <= 0x9F):
                        builder.Append(CultureInfo.InvariantCulture, $"&#x{rune.Value:X};");
                        break;
                    default: builder.Append(rune.ToString()); break;
                }
            }

            return builder.ToString();
        }

        /// <summary>
        /// Hides sensitive values in text before you log or display it: card numbers (all but the last 4 digits),
        /// email addresses, Caltrop keys and API keys, bearer and JWT tokens, and values like <c>password=...</c>.
        /// </summary>
        /// <param name="text">The text, such as a log message or request body. <see langword="null"/> gives an empty string.</param>
        /// <returns>The text with sensitive values replaced by <c>****</c>.</returns>
        /// <remarks>It recognizes common patterns, so it reduces leaks but cannot promise to catch every secret.</remarks>
        public static string Mask(string? text)
        {
            if (string.IsNullOrEmpty(text))
            {
                return string.Empty;
            }

            try
            {
                text = NamedSecret().Replace(text, match => match.Groups[1].Value + match.Groups[2].Value + Hidden);
                text = Bearer().Replace(text, match => match.Groups[1].Value + Hidden);
                text = Jwt().Replace(text, "eyJ" + Hidden);
                text = CaltropSecret().Replace(text, match => match.Groups[1].Value + "_" + Hidden);
                text = ApiKeyLike().Replace(text, match => ApiKeys.TrySplit(match.Value, out string prefix, out _) ? prefix + "_" + Hidden : match.Value);
                text = CardNumber().Replace(text, match => MaskCard(match.Value));
                text = Email().Replace(text, match => match.Value[0] + "***" + match.Value[match.Value.IndexOf('@', StringComparison.Ordinal)..]);
                return text;
            }
            catch (RegexMatchTimeoutException)
            {
                return "[hidden: too complex to mask safely]";
            }
        }

        /// <summary>
        /// Removes characters that can hide or disguise text: control characters, zero-width characters,
        /// right-to-left overrides (which can make <c>photo_gpj.exe</c> look like <c>photo_exe.jpg</c>) and
        /// "noncharacters" such as U+FFFE. Keeps tabs and new lines, fixes broken Unicode and normalizes it (NFC).
        /// </summary>
        /// <param name="text">The text. <see langword="null"/> gives an empty string.</param>
        /// <returns>The cleaned text.</returns>
        public static string CleanText(string? text)
        {
            if (string.IsNullOrEmpty(text))
            {
                return string.Empty;
            }

            var builder = new StringBuilder(text.Length);
            foreach (Rune rune in text.EnumerateRunes())
            {
                int value = rune.Value;
                bool invisible =
                    (value < 0x20 && value is not ('\t' or '\n' or '\r'))
                    || value is (>= 0x7F and <= 0x9F)
                    || value is (>= 0x200B and <= 0x200F) or (>= 0x202A and <= 0x202E) or (>= 0x2060 and <= 0x2069) or 0xFEFF or 0x061C or 0x180E
                    || value is (>= 0xFDD0 and <= 0xFDEF) || (value & 0xFFFE) == 0xFFFE; // Unicode's noncharacters
                if (!invisible)
                {
                    builder.Append(rune.ToString());
                }
            }

            string cleaned = builder.ToString();
            try
            {
                return cleaned.IsNormalized(NormalizationForm.FormC) ? cleaned : cleaned.Normalize(NormalizationForm.FormC);
            }
            catch (ArgumentException)
            {
                return cleaned; // the platform cannot normalize it; it is clean all the same
            }
        }

        /// <summary>
        /// <see langword="true"/> if a link is safe to put in an <c>href</c> or <c>src</c>: an http, https or mailto
        /// link, or a relative link. Blocks <c>javascript:</c>, <c>data:</c>, <c>vbscript:</c> and every other scheme,
        /// including disguised ones like <c>" JaVa&#x09;script:"</c>.
        /// </summary>
        /// <param name="url">The link from outside.</param>
        /// <returns><see langword="true"/> if it is safe to use as a link.</returns>
        public static bool IsSafeLink(string? url)
        {
            if (string.IsNullOrWhiteSpace(url))
            {
                return false;
            }

            // Browsers ignore control characters and whitespace inside the scheme, so remove them before looking.
            var builder = new StringBuilder(url.Length);
            foreach (char c in url)
            {
                if (c > ' ' && !char.IsWhiteSpace(c) && !char.IsControl(c))
                {
                    builder.Append(c);
                }
            }

            string compact = builder.ToString();
            int end = compact.IndexOfAny(['/', '?', '#']);
            string head = end < 0 ? compact : compact[..end];
            if (head.Contains('&', StringComparison.Ordinal))
            {
                return false; // an HTML entity such as "javascript&#58;" would become a scheme once the page decodes it
            }

            int colon = head.IndexOf(':', StringComparison.Ordinal);
            if (colon < 0)
            {
                return !compact.StartsWith('\\');
            }

            string scheme = head[..colon].ToLowerInvariant();
            return scheme is "http" or "https" or "mailto";
        }

        private static string MaskCard(string match)
        {
            int digits = 0;
            foreach (char c in match)
            {
                digits += char.IsAsciiDigit(c) ? 1 : 0;
            }

            if (digits is < 13 or > 19 || !PassesLuhn(match))
            {
                return match;
            }

            var builder = new StringBuilder(match.Length);
            int seen = 0;
            foreach (char c in match)
            {
                if (char.IsAsciiDigit(c))
                {
                    seen++;
                    builder.Append(seen > digits - 4 ? c : '*');
                }
                else
                {
                    builder.Append(c);
                }
            }

            return builder.ToString();
        }

        private static bool PassesLuhn(string text)
        {
            int sum = 0;
            bool doubleIt = false;
            for (int i = text.Length - 1; i >= 0; i--)
            {
                if (!char.IsAsciiDigit(text[i]))
                {
                    continue;
                }

                int digit = text[i] - '0';
                if (doubleIt)
                {
                    digit *= 2;
                    if (digit > 9)
                    {
                        digit -= 9;
                    }
                }

                sum += digit;
                doubleIt = !doubleIt;
            }

            return sum % 10 == 0;
        }

        private static bool IsUnder(string path, string rootWithSeparator)
        {
            StringComparison comparison = OperatingSystem.IsWindows() || OperatingSystem.IsMacOS() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
            return path.StartsWith(rootWithSeparator, comparison) && path.Length > rootWithSeparator.Length;
        }

        private static bool IsReservedWindowsName(string segment)
        {
            string stem = segment.Split('.')[0].TrimEnd(' ');
            foreach (string reserved in s_reservedWindowsNames)
            {
                if (string.Equals(stem, reserved, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            return false;
        }

        private static CaltropException Unsafe(string detail) =>
            new(CaltropErrorCode.UnsafeInput, $"Unsafe path rejected: {detail}");

        [GeneratedRegex("""(?i)\b(password|passwd|pwd|pass|secret|client[_-]?secret|token|access[_-]?token|refresh[_-]?token|api[_-]?key|access[_-]?key)("?\s*[=:]\s*)("[^"]*"|'[^']*'|[^\s;,&"']+)""", RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 1000)]
        private static partial Regex NamedSecret();

        [GeneratedRegex("""(?i)\b(bearer\s+)[A-Za-z0-9._~+/=-]{8,}""", RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 1000)]
        private static partial Regex Bearer();

        [GeneratedRegex("""\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]+""", RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 1000)]
        private static partial Regex Jwt();

        [GeneratedRegex("""\b(ctk|ctprv|whsec)_[A-Za-z0-9_-]{16,}""", RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 1000)]
        private static partial Regex CaltropSecret();

        [GeneratedRegex("""\b[A-Za-z][A-Za-z0-9_]{0,31}_[A-Za-z0-9]{38}\b""", RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 1000)]
        private static partial Regex ApiKeyLike();

        [GeneratedRegex("""(?<![0-9])[0-9](?:[ -]?[0-9]){12,18}(?![0-9])""", RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 1000)]
        private static partial Regex CardNumber();

        [GeneratedRegex("""[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}""", RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 1000)]
        private static partial Regex Email();
    }
}
