namespace CaltropSecurity.Tests;

public sealed class LogTests : IDisposable
{
    private readonly CaltropKey _key = CaltropKey.Generate();
    private readonly TempFolder _folder = new();

    public void Dispose() => _folder.Dispose();

    private string LogPath => _folder.File("security.log");

    [Fact]
    public void A_fresh_log_verifies_and_reads_back()
    {
        using (var log = new CaltropLog(LogPath, _key))
        {
            log.Write("alice logged in");
            log.Write("tabs\tand\nnew lines and a \\ backslash");

            CaltropLogCheck check = log.Verify();
            IReadOnlyList<CaltropLogEntry> entries = log.Read();

            Assert.True(check.IsIntact, check.Problem);
            Assert.Equal(2, check.Entries);
            Assert.Equal("alice logged in", entries[0].Message);
            Assert.Equal("tabs\tand\nnew lines and a \\ backslash", entries[1].Message);
            Assert.Equal(2, entries[1].Number);
        }

        Assert.Equal(3, File.ReadAllLines(LogPath).Length); // one entry per line, plus the header
    }

    [Fact]
    public void Reopening_continues_the_chain()
    {
        using (var log = new CaltropLog(LogPath, _key))
        {
            log.Write("one");
        }

        using (var log = new CaltropLog(LogPath, _key))
        {
            log.Write("two");
            Assert.True(log.Verify().IsIntact);
            Assert.Equal(["one", "two"], log.Read().Select(e => e.Message));
        }
    }

    [Fact]
    public void A_header_written_differently_is_found()
    {
        CaltropKey key = _key;
        while (!key.Id.Any(char.IsAsciiLetter))
        {
            key = CaltropKey.Generate(); // a key id with a letter in it, so its case can change
        }

        using (var log = new CaltropLog(LogPath, key))
        {
            log.Write("a");
        }

        string text = File.ReadAllText(LogPath);
        int end = text.IndexOf('\n');
        File.WriteAllText(LogPath, text[..end].Replace(key.Id, key.Id.ToUpperInvariant(), StringComparison.Ordinal) + text[end..]);

        CaltropLogCheck check = CaltropLog.Verify(LogPath, key);

        Assert.False(check.IsIntact);
        Assert.Equal(1, check.Line);
    }

    [Theory]
    [InlineData("\r\r\n")]
    [InlineData(" \n")]
    [InlineData("\t\n")]
    public void Anything_after_a_check_value_is_found(string ending)
    {
        WriteEntries("a", "b");
        string text = File.ReadAllText(LogPath);
        int end = text.IndexOf('\n', text.IndexOf('\n') + 1); // the end of the first entry
        File.WriteAllText(LogPath, text[..end] + ending + text[(end + 1)..]);

        CaltropLogCheck check = CaltropLog.Verify(LogPath, _key);

        Assert.False(check.IsIntact);
        Assert.Equal(2, check.Line);
    }

    [Fact]
    public void An_edited_entry_is_found()
    {
        WriteEntries("user=alice amount=10", "user=bob amount=20", "user=carol amount=30");
        string[] lines = File.ReadAllLines(LogPath);
        lines[2] = lines[2].Replace("amount=20", "amount=2000", StringComparison.Ordinal);
        File.WriteAllLines(LogPath, lines);

        CaltropLogCheck check = CaltropLog.Verify(LogPath, _key);

        Assert.False(check.IsIntact);
        Assert.Equal(3, check.Line);
        Assert.Contains("Entry 2", check.Problem);
        Assert.Contains("changed", check.Problem);
    }

    [Fact]
    public void A_deleted_entry_is_found()
    {
        WriteEntries("a", "b", "c");
        List<string> lines = [.. File.ReadAllLines(LogPath)];
        lines.RemoveAt(2);
        File.WriteAllLines(LogPath, lines);

        CaltropLogCheck check = CaltropLog.Verify(LogPath, _key);

        Assert.False(check.IsIntact);
        Assert.Contains("Entry 2 is missing", check.Problem);
    }

    [Fact]
    public void Swapped_entries_are_found()
    {
        WriteEntries("a", "b", "c");
        string[] lines = File.ReadAllLines(LogPath);
        (lines[1], lines[2]) = (lines[2], lines[1]);
        File.WriteAllLines(LogPath, lines);

        Assert.False(CaltropLog.Verify(LogPath, _key).IsIntact);
    }

    [Fact]
    public void A_forged_entry_is_found()
    {
        WriteEntries("a");
        File.AppendAllText(LogPath, "2\t2026-11-16T12:00:00.000Z\tadmin approved mallory\tAAAAAAAAAAAAAAAAAAAAAA\n");

        CaltropLogCheck check = CaltropLog.Verify(LogPath, _key);

        Assert.False(check.IsIntact);
        Assert.Contains("Entry 2", check.Problem);
    }

    [Fact]
    public void An_entry_copied_from_another_log_with_the_same_key_is_found()
    {
        string other = _folder.File("other.log");
        using (var log = new CaltropLog(other, _key))
        {
            log.Write("x");
            log.Write("admin approved mallory");
        }

        WriteEntries("a", "b", "c");
        string[] lines = File.ReadAllLines(LogPath);
        lines[2] = File.ReadAllLines(other)[2]; // a genuine entry 2, but from a different log

        File.WriteAllLines(LogPath, lines);

        CaltropLogCheck check = CaltropLog.Verify(LogPath, _key);
        Assert.False(check.IsIntact);
        Assert.Equal(3, check.Line);
    }

    [Fact]
    public void Deleting_the_newest_entries_is_found_with_a_saved_Head()
    {
        string head;
        using (var log = new CaltropLog(LogPath, _key))
        {
            log.Write("a");
            log.Write("b");
            log.Write("c");
            head = log.Head;
        }

        string[] lines = File.ReadAllLines(LogPath);
        File.WriteAllLines(LogPath, lines[..^1]);

        Assert.True(CaltropLog.Verify(LogPath, _key).IsIntact);
        CaltropLogCheck check = CaltropLog.Verify(LogPath, _key, head);
        Assert.False(check.IsIntact);
        Assert.Contains("newest entries were deleted", check.Problem);

        File.WriteAllText(LogPath, string.Empty);
        Assert.False(CaltropLog.Verify(LogPath, _key, head).IsIntact);
    }

    [Fact]
    public void A_log_from_another_key_is_refused()
    {
        WriteEntries("a");
        using var other = CaltropKey.Generate();

        TestData.Throws(CaltropErrorCode.KeyMismatch, () => new CaltropLog(LogPath, other));
        Assert.False(CaltropLog.Verify(LogPath, other).IsIntact);
    }

    [Fact]
    public void Read_refuses_a_tampered_log()
    {
        WriteEntries("a", "b");
        string[] lines = File.ReadAllLines(LogPath);
        lines[1] = lines[1].Replace("\ta\t", "\tA\t", StringComparison.Ordinal);
        File.WriteAllLines(LogPath, lines);

        using var log = new CaltropLog(LogPath, _key);
        TestData.Throws(CaltropErrorCode.AuthenticationFailed, () => log.Read());
    }

    private void WriteEntries(params string[] messages)
    {
        using var log = new CaltropLog(LogPath, _key);
        foreach (string message in messages)
        {
            log.Write(message);
        }
    }
}

[Collection(GlobalState.Name)]
public sealed class LogAlarmTests : IDisposable
{
    private readonly TempFolder _folder = new();

    public LogAlarmTests() => GlobalState.Reset();

    public void Dispose()
    {
        _folder.Dispose();
        GlobalState.Reset();
    }

    [Fact]
    public void Opening_a_tampered_log_raises_an_alarm_and_keeps_logging()
    {
        string path = _folder.File("app.log");
        using var key = CaltropKey.Generate();
        using (var log = new CaltropLog(path, key))
        {
            log.Write("a");
            log.Write("b");
        }

        string[] lines = File.ReadAllLines(path);
        lines[1] = lines[1].Replace("\ta\t", "\tz\t", StringComparison.Ordinal);
        File.WriteAllLines(path, lines);
        using var alarms = new AlarmRecorder();

        using (var log = new CaltropLog(path, key))
        {
            log.Write("c");
        }

        Assert.Equal(CaltropAlarmKind.Tampering, Assert.Single(alarms.Alarms).Kind);
        Assert.Contains("\tc\t", File.ReadAllText(path));
    }

    [Fact]
    public void The_log_uses_the_default_key_when_none_is_given()
    {
        Caltrop.UseKey(CaltropKey.Generate());
        string path = _folder.File("default.log");

        using (var log = new CaltropLog(path))
        {
            log.Write("hello");
        }

        Assert.True(CaltropLog.Verify(path).IsIntact);
    }
}
