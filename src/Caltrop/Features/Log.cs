using System.Buffers.Text;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using CaltropSecurity.Internal;

/// <summary>
/// A tamper-proof log file: a plain text log where every entry is chained to the one before it with your key. If
/// anyone edits, deletes, inserts or reorders entries, <see cref="Verify(string?)"/> says where, and sets off a
/// <see cref="CaltropAlarmKind.Tampering"/> alarm.
/// </summary>
/// <example>
/// <code>
/// using var log = new CaltropLog("security.log");          // uses the default key
/// log.Write("alice logged in");
/// log.Write("alice changed her password");
///
/// CaltropLogCheck check = log.Verify();
/// if (!check.IsIntact) Console.WriteLine(check.Problem);   // e.g. "Entry 2 (line 3) was changed."
///
/// Caltrop.Traps.Log = log;                                  // optional: record every alarm here too
/// </code>
/// </example>
/// <remarks>
/// <para>
/// The file stays readable in any text editor: one entry per line, as <c>number, time, message, check</c>
/// separated by tabs. Only someone with the key can add entries that verify.
/// </para>
/// <para>
/// Several programs, or several copies of your app, can write to the same log at once: entries are added one at a
/// time, so none is lost or mixed up. (Caltrop keeps a small <c>.lock</c> file next to the log for this.)
/// </para>
/// <para>
/// A log cannot notice that its newest entries (or the whole file) were deleted, because what is left still
/// verifies. To catch that, save <see cref="Head"/> somewhere else now and then, and pass it to
/// <see cref="Verify(string?)"/>.
/// </para>
/// </remarks>
public sealed class CaltropLog : IDisposable, IWipeable
{
    /// <summary>The longest message <see cref="Write(string)"/> accepts.</summary>
    public const int MaxMessageLength = 1_000_000;

    private const string HeaderPrefix = "# Caltrop log v1, key ";
    private const int MacSize = 16;
    private const int MacTextLength = 22; // Base64Url of 16 bytes

    /// <summary>Logs up to this size are checked as they are opened. Bigger ones are checked by <see cref="Verify(string?)"/> only, so opening stays quick.</summary>
    private const long CheckWhenOpenedUpTo = 8 * 1024 * 1024;

    /// <summary>No real entry comes near this; anything longer is damage, and is skipped without being held in memory.</summary>
    private const int MaxLineLength = 16 * 1024 * 1024;

    private readonly Lock _gate = new();
    private readonly byte[] _logKey;
    private readonly byte[] _keyId;
    private volatile bool _closed;

    /// <summary>Opens a log file, creating it (and its folder) if needed, and checks what is already in it.</summary>
    /// <param name="path">The log file.</param>
    /// <param name="key">The key that protects the log. Defaults to the default key.</param>
    /// <exception cref="CaltropException">The file is a log made with a different key (<see cref="CaltropErrorCode.KeyMismatch"/>).</exception>
    /// <remarks>
    /// If the existing entries were tampered with, the alarm goes off, and new entries are still added after them.
    /// Logs over 8 MB are not checked when they are opened, so that opening stays quick; <see cref="Verify(string?)"/> checks them.
    /// </remarks>
    public CaltropLog(string path, CaltropKey? key = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        key ??= Caltrop.DefaultKeys.Primary;
        Path = System.IO.Path.GetFullPath(path);
        _keyId = key.IdBytes.ToArray();
        _logKey = GC.AllocateUninitializedArray<byte>(Format.KeySize, pinned: true);
        key.Derive(Labels.Log, default, _logKey);
        try
        {
            SharedFile.CreateFolderFor(Path);
            using (SharedFile.Lock(Path))
            using (FileStream file = OpenForWriting())
            {
                Prepare(file);
            }

            // Checked after the lock is released, so the alarm can be written to this same log.
            if (new FileInfo(Path).Length <= CheckWhenOpenedUpTo)
            {
                CheckAndAlarm(Path, _logKey, _keyId, expectedHead: null, entries: null);
            }
        }
        catch
        {
            CryptographicOperations.ZeroMemory(_logKey);
            throw;
        }

        Wipeables.Register(this);
    }

    /// <summary>The full path of the log file.</summary>
    public string Path { get; }

    /// <summary>
    /// The newest entry's number and check value, like <c>42:Xq3...</c>. Save it somewhere else (a database, another
    /// machine) and pass it to <see cref="Verify(string?)"/> later to catch deleted newest entries or a deleted file.
    /// </summary>
    public string Head
    {
        get
        {
            lock (_gate)
            {
                ThrowIfClosed();
                using FileStream? file = SharedFile.TryOpenRead(Path);
                (long number, byte[] mac) = file is null ? (0, new byte[MacSize]) : ReadLast(file);
                return FormatHead(number, mac);
            }
        }
    }

    /// <summary>Adds an entry. It is written to the file straight away.</summary>
    /// <param name="message">What happened. Any text up to <see cref="MaxMessageLength"/> characters: tabs and new lines are escaped so one entry stays on one line.</param>
    public void Write(string message)
    {
        ArgumentNullException.ThrowIfNull(message);
        if (message.Length > MaxMessageLength)
        {
            throw new ArgumentException("A log entry can be at most 1,000,000 characters.", nameof(message));
        }

        string text = Escape(message);
        lock (_gate)
        {
            ThrowIfClosed();
            using (SharedFile.Lock(Path))
            using (FileStream file = OpenForWriting())
            {
                Prepare(file);
                (long last, byte[] previous) = ReadLast(file);
                string body = string.Create(CultureInfo.InvariantCulture, $"{last + 1}\t{DateTimeOffset.UtcNow:yyyy-MM-dd'T'HH:mm:ss.fff'Z'}\t{text}");
                byte[] mac = Mac(_logKey, previous, body);
                Caltrop.Traps.ThrowIfLockedDownAfterUse();
                Append(file, $"{body}\t{Base64Url.EncodeToString(mac)}\n");
            }
        }
    }

    /// <summary>Checks every entry in the file. A problem sets off the alarm.</summary>
    /// <param name="expectedHead">Optional. A <see cref="Head"/> value saved earlier, to also catch deleted newest entries.</param>
    /// <returns>Whether the log is intact and, if not, the first problem found.</returns>
    public CaltropLogCheck Verify(string? expectedHead = null)
    {
        lock (_gate)
        {
            ThrowIfClosed();
            return CheckAndAlarm(Path, _logKey, _keyId, expectedHead, entries: null);
        }
    }

    /// <summary>Checks a log file without opening it for writing. A problem sets off the alarm.</summary>
    /// <param name="path">The log file.</param>
    /// <param name="key">The key it was written with. Defaults to the default keys.</param>
    /// <param name="expectedHead">Optional. A <see cref="Head"/> value saved earlier.</param>
    /// <returns>Whether the log is intact and, if not, the first problem found.</returns>
    /// <exception cref="FileNotFoundException">There is no file at <paramref name="path"/>.</exception>
    public static CaltropLogCheck Verify(string path, CaltropKey? key = null, string? expectedHead = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        string fullPath = System.IO.Path.GetFullPath(path);
        if (!File.Exists(fullPath))
        {
            throw new FileNotFoundException($"There is no log at {fullPath}.", fullPath);
        }

        CaltropKey chosen = key ?? KeyFor(fullPath, Caltrop.DefaultKeys);
        byte[] logKey = new byte[Format.KeySize];
        try
        {
            chosen.Derive(Labels.Log, default, logKey);
            return CheckAndAlarm(fullPath, logKey, chosen.IdBytes.ToArray(), expectedHead, entries: null);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(logKey);
        }
    }

    /// <summary>Reads every entry, after checking the whole log.</summary>
    /// <returns>The entries, oldest first.</returns>
    /// <exception cref="CaltropException">The log was tampered with (<see cref="CaltropErrorCode.AuthenticationFailed"/>). The alarm has gone off.</exception>
    public IReadOnlyList<CaltropLogEntry> Read()
    {
        lock (_gate)
        {
            ThrowIfClosed();
            var entries = new List<CaltropLogEntry>();
            CaltropLogCheck check = CheckAndAlarm(Path, _logKey, _keyId, expectedHead: null, entries);
            if (!check.IsIntact)
            {
                throw new CaltropException(CaltropErrorCode.AuthenticationFailed, $"The log was tampered with, so its entries cannot be trusted: {check.Problem}");
            }

            return entries;
        }
    }

    /// <summary>Wipes the log key from memory. The file stays as it is.</summary>
    public void Dispose()
    {
        lock (_gate)
        {
            _closed = true;
            CryptographicOperations.ZeroMemory(_logKey);
        }
    }

    void IWipeable.Wipe()
    {
        // No lock: a lockdown must never wait. Every method checks the lockdown before and after using the key.
        _closed = true;
        CryptographicOperations.ZeroMemory(_logKey);
    }

    /// <summary>The key in <paramref name="keys"/> that an existing log was written with, or the primary key for a new log.</summary>
    internal static CaltropKey KeyFor(string path, CaltropKeyRing keys)
    {
        using FileStream? file = SharedFile.TryOpenRead(path);
        if (file is not null && TryReadHeaderKeyId(ReadFirstLine(file), out byte[] keyId))
        {
            return keys.FirstOrDefault(key => key.Matches(keyId)) ?? keys.Primary;
        }

        return keys.Primary;
    }

    private void ThrowIfClosed()
    {
        Caltrop.Traps.ThrowIfLockedDown();
        ObjectDisposedException.ThrowIf(_closed, this);
    }

    private FileStream OpenForWriting() =>
        SharedFile.Retry(Path, () => new FileStream(Path, SharedFile.Options(FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.ReadWrite | FileShare.Delete, bufferSize: 0)));

    /// <summary>
    /// Gets the open file ready for a new entry: writes the header to a new log, refuses a log made with another
    /// key, and ends a cut-off last line (left by a crash, or by someone editing the file) so the next entry
    /// starts on a line of its own.
    /// </summary>
    private void Prepare(FileStream file)
    {
        if (file.Length == 0)
        {
            Append(file, $"{HeaderPrefix}{Convert.ToHexStringLower(_keyId)}\n");
            return;
        }

        file.Position = 0;
        if (TryReadHeaderKeyId(ReadFirstLine(file), out byte[] fileKeyId) && !fileKeyId.AsSpan().SequenceEqual(_keyId))
        {
            throw new CaltropException(
                CaltropErrorCode.KeyMismatch,
                $"The log {Path} was written with a different key (key id {Convert.ToHexStringLower(fileKeyId)}). Open it with that key, or use a new file.");
        }

        file.Position = file.Length - 1;
        if (file.ReadByte() != '\n')
        {
            Append(file, "\n");
        }
    }

    private static void Append(FileStream file, string text)
    {
        file.Seek(0, SeekOrigin.End);
        file.Write(Encoding.UTF8.GetBytes(text)); // one write, so readers see whole lines
    }

    private static string ReadFirstLine(FileStream file)
    {
        Span<byte> start = stackalloc byte[128];
        int read = file.ReadAtLeast(start, start.Length, throwOnEndOfStream: false);
        int end = start[..read].IndexOf((byte)'\n');
        ReadOnlySpan<byte> line = start[..(end < 0 ? read : end)];
        if (line.StartsWith(Encoding.UTF8.Preamble))
        {
            line = line[Encoding.UTF8.Preamble.Length..]; // a text editor may add one, like Windows line endings
        }

        return WithoutCarriageReturn(Encoding.UTF8.GetString(line));
    }

    /// <summary>The number and check value of the last whole entry, which the next entry is chained to (0 and zeros if there is none).</summary>
    private static (long Number, byte[] Mac) ReadLast(FileStream file)
    {
        // Usually the last entry is in the last few kilobytes. Look further back only if it is not.
        long length = file.Length;
        for (int window = 4096; window <= 1024 * 1024; window *= 4)
        {
            long start = Math.Max(0, length - window);
            byte[] buffer = new byte[length - start];
            file.Position = start;
            file.ReadExactly(buffer);
            string[] lines = Encoding.UTF8.GetString(buffer).Split('\n');

            // The first piece is the header, or cut off by the window; the last is unfinished, or empty.
            for (int i = lines.Length - 2; i >= 1; i--)
            {
                if (TryParseEntry(WithoutCarriageReturn(lines[i]), out _, out long number, out byte[] mac))
                {
                    return (number, mac);
                }
            }

            if (start == 0)
            {
                return (0, new byte[MacSize]);
            }
        }

        // A megabyte of damage at the end: read the whole file, a line at a time.
        (long Number, byte[] Mac) last = (0, new byte[MacSize]);
        file.Position = 0;
        bool header = true;
        foreach (string line in ReadLines(file))
        {
            if (!header && TryParseEntry(line, out _, out long number, out byte[] mac))
            {
                last = (number, mac);
            }

            header = false;
        }

        return last;
    }

    private static CaltropLogCheck CheckAndAlarm(string path, byte[] logKey, byte[] keyId, string? expectedHead, List<CaltropLogEntry>? entries)
    {
        CaltropLogCheck check;
        using (FileStream? file = SharedFile.TryOpenRead(path))
        {
            // A deleted log has no lines: only a saved Head can tell that anything is missing.
            check = CheckLines(file is null ? [] : ReadLines(file), logKey, keyId, expectedHead, entries);
        }

        Caltrop.Traps.ThrowIfLockedDownAfterUse();
        if (!check.IsIntact)
        {
            Tampering.Raise("Log", $"The log {path} was tampered with: {check.Problem}", path);
        }

        return check;
    }

    /// <summary>Checks the lines in order, and collects the entries if <paramref name="entries"/> is given.</summary>
    private static CaltropLogCheck CheckLines(IEnumerable<string> lines, byte[] logKey, byte[] keyId, string? expectedHead, List<CaltropLogEntry>? entries)
    {
        long headNumber = -1;
        byte[]? headMac = null;
        if (expectedHead is not null && !TryParseHead(expectedHead, out headNumber, out headMac))
        {
            throw new ArgumentException("This is not a Head value from a CaltropLog.", nameof(expectedHead));
        }

        string? problem = null;
        int? problemLine = null;
        void Report(string message, int line)
        {
            if (problem is null)
            {
                problem = message;
                problemLine = line;
            }
        }

        byte[] previous = new byte[MacSize];
        long expected = 1;
        long lastNumber = 0;
        bool headSeen = false;
        int lineNumber = 0;
        foreach (string line in lines)
        {
            lineNumber++;
            if (lineNumber == 1)
            {
                if (!TryReadHeaderKeyId(line, out byte[] fileKeyId))
                {
                    Report("The first line is not a Caltrop log header: the file was changed, or is not a Caltrop log.", 1);
                }
                else if (!fileKeyId.AsSpan().SequenceEqual(keyId))
                {
                    Report($"The log was written with a different key (key id {Convert.ToHexStringLower(fileKeyId)}).", 1);
                }

                continue;
            }

            if (!TryParseEntry(line, out string[] parts, out long number, out byte[] stored))
            {
                Report($"Line {lineNumber} is damaged.", lineNumber);
                continue;
            }

            if (number > expected)
            {
                Report(number == expected + 1 ? $"Entry {expected} is missing (deleted) before line {lineNumber}." : $"Entries {expected} to {number - 1} are missing (deleted) before line {lineNumber}.", lineNumber);
            }
            else if (number < expected)
            {
                Report($"Entry {number} at line {lineNumber} is out of order or repeated.", lineNumber);
            }

            byte[] actual = Mac(logKey, previous, $"{parts[0]}\t{parts[1]}\t{parts[2]}");
            if (number == expected && !CryptographicOperations.FixedTimeEquals(actual, stored))
            {
                Report($"Entry {number} (line {lineNumber}) was changed.", lineNumber);
            }

            if (number == headNumber && headMac is not null)
            {
                headSeen = true;
                if (!CryptographicOperations.FixedTimeEquals(stored, headMac))
                {
                    Report($"Entry {number} (line {lineNumber}) is not the entry that was there before: the log was rewritten.", lineNumber);
                }
            }

            if (entries is not null && problem is null
                && DateTimeOffset.TryParse(parts[1], CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out DateTimeOffset time))
            {
                entries.Add(new CaltropLogEntry(number, time, Unescape(parts[2])));
            }

            previous = stored;
            expected = number + 1;
            lastNumber = number;
        }

        if (lineNumber == 0 && headNumber > 0)
        {
            Report($"The log is empty, but it had {headNumber} entries: it was deleted or emptied.", 1);
        }
        else if (headNumber > 0 && !headSeen)
        {
            Report($"The log ends at entry {lastNumber}, but it had {headNumber} entries: the newest entries were deleted.", lineNumber);
        }

        return new CaltropLogCheck(problem is null, lastNumber, problem, problemLine);
    }

    /// <summary>
    /// Reads the lines of the file one at a time, so a big log never has to fit in memory. Windows line endings are
    /// fine. A last line with no new line after it is left out: another program is still writing it.
    /// </summary>
    private static IEnumerable<string> ReadLines(FileStream file)
    {
        using var reader = new StreamReader(file, Encoding.UTF8, detectEncodingFromByteOrderMarks: false, bufferSize: 65536, leaveOpen: true);
        var line = new StringBuilder();
        bool tooLong = false;
        char[] buffer = new char[65536];
        int count;
        while ((count = reader.Read(buffer, 0, buffer.Length)) > 0)
        {
            ReadOnlyMemory<char> rest = buffer.AsMemory(0, count);
            int newLine;
            while ((newLine = rest.Span.IndexOf('\n')) >= 0)
            {
                if (!tooLong)
                {
                    line.Append(rest.Span[..newLine]);
                }

                yield return tooLong ? string.Empty : WithoutCarriageReturn(line.ToString());
                line.Clear();
                tooLong = false;
                rest = rest[(newLine + 1)..];
            }

            if (!tooLong && line.Length + rest.Length > MaxLineLength)
            {
                tooLong = true; // damaged: an empty line is reported in its place
                line.Clear();
            }
            else if (!tooLong)
            {
                line.Append(rest.Span);
            }
        }
    }

    private static bool TryParseEntry(string line, out string[] parts, out long number, out byte[] mac)
    {
        number = 0;
        mac = [];
        parts = line.Split('\t');
        return parts.Length == 4
            && long.TryParse(parts[0], NumberStyles.None, CultureInfo.InvariantCulture, out number)
            && parts[3].Length == MacTextLength // exactly, so nothing can hide around it
            && Encodings.TryFromBase64Url(parts[3], out mac)
            && mac.Length == MacSize;
    }

    /// <summary>One line ending (Windows "\r\n") is fine; anything more is a change to the file.</summary>
    private static string WithoutCarriageReturn(string line) => line.EndsWith('\r') ? line[..^1] : line;

    private static byte[] Mac(byte[] logKey, byte[] previous, string body)
    {
        byte[] data = new byte[previous.Length + Encoding.UTF8.GetByteCount(body)];
        previous.CopyTo(data, 0);
        Encoding.UTF8.GetBytes(body, data.AsSpan(previous.Length));
        return HMACSHA256.HashData(logKey, data)[..MacSize];
    }

    private static string FormatHead(long number, byte[] mac) =>
        $"{number.ToString(CultureInfo.InvariantCulture)}:{Base64Url.EncodeToString(mac)}";

    private static bool TryReadHeaderKeyId(string line, out byte[] keyId)
    {
        keyId = [];
        if (!line.StartsWith(HeaderPrefix, StringComparison.Ordinal))
        {
            return false;
        }

        ReadOnlySpan<char> hex = line.AsSpan(HeaderPrefix.Length);
        if (hex.Length != Format.KeyIdSize * 2 || !Encodings.IsLowercaseHex(hex))
        {
            return false;
        }

        keyId = Convert.FromHexString(hex);
        return true;
    }

    private static bool TryParseHead(string head, out long number, out byte[] mac)
    {
        number = 0;
        mac = [];
        head = head.Trim();
        int colon = head.IndexOf(':', StringComparison.Ordinal);
        return colon > 0
            && long.TryParse(head.AsSpan(0, colon), NumberStyles.None, CultureInfo.InvariantCulture, out number)
            && Encodings.TryFromBase64Url(head.AsSpan(colon + 1), out mac)
            && (number == 0 || mac.Length == MacSize);
    }

    /// <summary>Keeps one entry on one line: escapes backslashes, tabs, new lines and other control characters.</summary>
    private static string Escape(string message)
    {
        var builder = new StringBuilder(message.Length + 8);
        foreach (Rune rune in message.EnumerateRunes())
        {
            switch (rune.Value)
            {
                case '\\': builder.Append(@"\\"); break;
                case '\t': builder.Append(@"\t"); break;
                case '\n': builder.Append(@"\n"); break;
                case '\r': builder.Append(@"\r"); break;
                case < 0x20 or 0x7F:
                    builder.Append(CultureInfo.InvariantCulture, $@"\u{rune.Value:x4}");
                    break;
                default: builder.Append(rune.ToString()); break;
            }
        }

        return builder.ToString();
    }

    private static string Unescape(string text)
    {
        var builder = new StringBuilder(text.Length);
        for (int i = 0; i < text.Length; i++)
        {
            if (text[i] != '\\' || i + 1 == text.Length)
            {
                builder.Append(text[i]);
                continue;
            }

            char next = text[++i];
            switch (next)
            {
                case 't': builder.Append('\t'); break;
                case 'n': builder.Append('\n'); break;
                case 'r': builder.Append('\r'); break;
                case 'u' when i + 4 < text.Length && int.TryParse(text.AsSpan(i + 1, 4), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out int code):
                    builder.Append((char)code);
                    i += 4;
                    break;
                default: builder.Append(next); break;
            }
        }

        return builder.ToString();
    }
}

/// <summary>The result of checking a <see cref="CaltropLog"/>.</summary>
public sealed class CaltropLogCheck
{
    internal CaltropLogCheck(bool isIntact, long entries, string? problem, int? line)
    {
        IsIntact = isIntact;
        Entries = entries;
        Problem = problem;
        Line = line;
    }

    /// <summary><see langword="true"/> if no entry was changed, deleted, added or moved.</summary>
    public bool IsIntact { get; }

    /// <summary>The number of the last entry in the file.</summary>
    public long Entries { get; }

    /// <summary>The first problem found, or <see langword="null"/> if the log is intact.</summary>
    public string? Problem { get; }

    /// <summary>The line of the file where the first problem was found (the header is line 1).</summary>
    public int? Line { get; }

    /// <summary>Returns "Intact (n entries)" or the problem.</summary>
    public override string ToString() => IsIntact ? $"Intact ({Entries} {(Entries == 1 ? "entry" : "entries")})" : $"Tampered: {Problem}";
}

/// <summary>One entry of a <see cref="CaltropLog"/>.</summary>
/// <param name="Number">Its position in the log, starting at 1.</param>
/// <param name="Time">When it was written (UTC).</param>
/// <param name="Message">The message.</param>
public sealed record CaltropLogEntry(long Number, DateTimeOffset Time, string Message);
