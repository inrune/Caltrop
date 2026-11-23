using System.Diagnostics;
using System.Text;
using CaltropSecurity.Internal;

namespace CaltropSecurity.Tests;

/// <summary>Several programs (or several copies of one app) using the same log at once.</summary>
public sealed class LogSharingTests : IDisposable
{
    private readonly CaltropKey _key = CaltropKey.Generate();
    private readonly TempFolder _folder = new();

    public void Dispose() => _folder.Dispose();

    private string LogPath => _folder.File("shared.log");

    [Fact]
    public void Two_logs_on_one_file_take_turns()
    {
        using var first = new CaltropLog(LogPath, _key);
        using var second = new CaltropLog(LogPath, _key);

        first.Write("one, from the first");
        second.Write("two, from the second");
        first.Write("three, from the first");

        Assert.True(CaltropLog.Verify(LogPath, _key).IsIntact);
        Assert.Equal(["one, from the first", "two, from the second", "three, from the first"], second.Read().Select(e => e.Message));
        Assert.Equal([1L, 2L, 3L], first.Read().Select(e => e.Number));
        Assert.Equal(first.Head, second.Head);
    }

    [Fact]
    public void Windows_line_endings_are_fine()
    {
        WriteEntries("a", "b");
        File.WriteAllText(LogPath, File.ReadAllText(LogPath).Replace("\n", "\r\n", StringComparison.Ordinal));

        Assert.True(CaltropLog.Verify(LogPath, _key).IsIntact);
        using var log = new CaltropLog(LogPath, _key);
        log.Write("c");
        Assert.Equal(["a", "b", "c"], log.Read().Select(e => e.Message));
    }

    [Fact]
    public void A_byte_order_mark_from_a_text_editor_is_fine()
    {
        WriteEntries("a");
        File.WriteAllBytes(LogPath, [.. Encoding.UTF8.Preamble, .. File.ReadAllBytes(LogPath)]);

        Assert.True(CaltropLog.Verify(LogPath, _key).IsIntact);
        using var otherKey = CaltropKey.Generate();
        TestData.Throws(CaltropErrorCode.KeyMismatch, () => new CaltropLog(LogPath, otherKey)); // the header is still read
        using var log = new CaltropLog(LogPath, _key);
        log.Write("b");
        Assert.Equal(["a", "b"], log.Read().Select(e => e.Message));
    }

    [Fact]
    public void A_cut_off_last_line_is_kept_apart_from_the_next_entry()
    {
        WriteEntries("a", "b");
        File.AppendAllText(LogPath, "3\t2026-11-17T10:00:00.000Z\thalf an ent"); // as if the app crashed mid-write

        // It may still be being written, so it is not counted yet.
        Assert.True(CaltropLog.Verify(LogPath, _key).IsIntact);

        using (var log = new CaltropLog(LogPath, _key))
        {
            log.Write("c");
        }

        string[] lines = File.ReadAllLines(LogPath);
        Assert.Equal(5, lines.Length);
        Assert.StartsWith("3\t", lines[4], StringComparison.Ordinal); // "c" carries on from "b"
        CaltropLogCheck check = CaltropLog.Verify(LogPath, _key);
        Assert.False(check.IsIntact);
        Assert.Equal(4, check.Line);
    }

    [Fact]
    public void Head_finds_the_newest_entry_after_damage_at_the_end()
    {
        string head;
        using (var log = new CaltropLog(LogPath, _key))
        {
            log.Write("a");
            head = log.Head;
            File.AppendAllText(LogPath, new string('x', 2 * 1024 * 1024) + "\n"); // a long damaged line
            Assert.Equal(head, log.Head);
            log.Write("b");
        }

        using var reopened = new CaltropLog(LogPath, _key);
        Assert.StartsWith("2:", reopened.Head, StringComparison.Ordinal);
    }

    [Fact]
    public void A_deleted_log_is_found_with_a_saved_Head_and_then_started_again()
    {
        using var log = new CaltropLog(LogPath, _key);
        log.Write("a");
        string head = log.Head;

        File.Delete(LogPath);

        CaltropLogCheck check = log.Verify(head);
        Assert.False(check.IsIntact);
        Assert.Contains("deleted", check.Problem, StringComparison.Ordinal);
        Assert.Throws<FileNotFoundException>(() => CaltropLog.Verify(LogPath, _key));

        log.Write("b");
        Assert.Equal(["b"], log.Read().Select(e => e.Message));
    }

    [Fact]
    public void Very_long_messages_are_refused()
    {
        using var log = new CaltropLog(LogPath, _key);

        Assert.Throws<ArgumentException>(() => log.Write(new string('x', CaltropLog.MaxMessageLength + 1)));
        log.Write(new string('x', 100_000));

        Assert.True(log.Verify().IsIntact);
    }

    [Fact]
    public void The_folder_is_made_if_needed()
    {
        string path = Path.Combine(_folder.Path, "logs", "2026", "app.log");

        using var log = new CaltropLog(path, _key);
        log.Write("hello");

        Assert.True(File.Exists(path));
    }

    [Fact]
    public void A_new_log_is_private_to_the_user()
    {
        using var log = new CaltropLog(LogPath, _key);

        if (OperatingSystem.IsWindows())
        {
            Assert.Skip("Windows files take their permissions from their folder.");
        }
        else
        {
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(LogPath));
        }
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

/// <summary>Several programs (or several copies of one app) using the same vault at once.</summary>
public sealed class VaultSharingTests : IDisposable
{
    private const string Password = "a long vault password 2026";
    private readonly CaltropKey _key = CaltropKey.Generate();
    private readonly TempFolder _folder = new();

    public void Dispose() => _folder.Dispose();

    private string VaultPath => _folder.File("shared.vault");

    [Fact]
    public void Two_vaults_on_one_file_see_each_others_changes()
    {
        using var first = CaltropVault.Create(VaultPath, _key);
        using var second = CaltropVault.Open(VaultPath, _key);

        first.Set("a", "1");
        Assert.Equal("1", second.Get("a"));

        second.Set("b", "2");
        Assert.Equal(["a", "b"], first.Names);

        first.Remove("a");
        Assert.False(second.Contains("a"));
        Assert.Equal(1, second.Count);
        Assert.Equal("2", first.Get("b"));
    }

    [Fact]
    public void Changes_made_at_the_same_time_are_all_kept()
    {
        CaltropVault.Create(VaultPath, _key).Dispose();

        Parallel.For(0, 4, writer =>
        {
            using var vault = CaltropVault.Open(VaultPath, _key);
            for (int i = 0; i < 10; i++)
            {
                vault.Set($"writer {writer} secret {i}", "x");
            }
        });

        using var opened = CaltropVault.Open(VaultPath, _key);
        Assert.Equal(40, opened.Count);
    }

    [Fact]
    public void A_password_changed_by_another_program_is_explained()
    {
        using var first = CaltropVault.Create(VaultPath, Password);
        using var second = CaltropVault.Open(VaultPath, Password);

        first.ChangePassword("another long password 2026");

        CaltropException ex = TestData.Throws(CaltropErrorCode.AuthenticationFailed, () => second.Get("x"));
        Assert.Contains("changed by another program", ex.Message, StringComparison.Ordinal);
        first.Set("x", "still works");
        Assert.Equal("still works", first.Get("x"));
    }

    [Fact]
    public void A_deleted_vault_file_is_saved_again_on_the_next_change()
    {
        using var vault = CaltropVault.Create(VaultPath, _key);
        vault.Set("a", "1");

        File.Delete(VaultPath);
        Assert.Equal("1", vault.Get("a"));
        vault.Set("b", "2");

        using var opened = CaltropVault.Open(VaultPath, _key);
        Assert.Equal(["a", "b"], opened.Names);
    }

    [Fact]
    public void A_vault_replaced_by_one_with_another_key_is_refused()
    {
        using var vault = CaltropVault.Create(VaultPath, _key);
        using var otherKey = CaltropKey.Generate();
        File.Delete(VaultPath);
        CaltropVault.Create(VaultPath, otherKey).Dispose();

        TestData.Throws(CaltropErrorCode.KeyMismatch, () => vault.Get("a"));
        TestData.Throws(CaltropErrorCode.KeyMismatch, () => vault.Set("a", "1"));
    }

    [Fact]
    public void Create_makes_the_folder_if_needed()
    {
        string path = Path.Combine(_folder.Path, "new", "folder", "app.vault");

        using var vault = CaltropVault.Create(path, _key);

        Assert.True(File.Exists(path));
    }

    [Fact]
    public void Saving_leaves_no_temporary_files_behind()
    {
        using var vault = CaltropVault.Create(VaultPath, _key);
        vault.Set("a", "1");
        vault.Remove("a");

        Assert.Empty(Directory.GetFiles(_folder.Path, "*.tmp"));
    }
}

/// <summary>Sharing files under pressure: no false alarms, waiting for a busy file, and clear errors.</summary>
[Collection(GlobalState.Name)]
public sealed class SharingStressTests : IDisposable
{
    private readonly CaltropKey _key = CaltropKey.Generate();
    private readonly TempFolder _folder = new();

    public SharingStressTests() => GlobalState.Reset();

    public void Dispose()
    {
        _folder.Dispose();
        GlobalState.Reset();
    }

    [Fact]
    public void Many_writers_at_once_lose_nothing_and_raise_no_false_alarms()
    {
        const int Writers = 4;
        const int Each = 40;
        string path = _folder.File("busy.log");
        using var alarms = new AlarmRecorder();

        Parallel.For(0, Writers, writer =>
        {
            using var log = new CaltropLog(path, _key); // opening checks the file while the others write
            for (int i = 0; i < Each; i++)
            {
                log.Write($"writer {writer} entry {i}");
                if (i % 10 == 0)
                {
                    Assert.True(log.Verify().IsIntact);
                }
            }
        });

        using var reader = new CaltropLog(path, _key);
        IReadOnlyList<CaltropLogEntry> entries = reader.Read();
        Assert.Equal(Enumerable.Range(1, Writers * Each).Select(n => (long)n), entries.Select(e => e.Number));
        Assert.Equal(Writers * Each, entries.Select(e => e.Message).Distinct().Count());
        Assert.Empty(alarms.Alarms);
    }

    [Fact]
    public void A_writer_waits_while_another_holds_the_lock()
    {
        string path = _folder.File("wait.log");
        using var log = new CaltropLog(path, _key);
        var held = new FileStream(path + ".lock", FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        Task release = Task.Run(async () =>
        {
            await Task.Delay(300);
            await held.DisposeAsync();
        });

        var watch = Stopwatch.StartNew();
        log.Write("after the wait");
        watch.Stop();
        release.GetAwaiter().GetResult();

        Assert.True(watch.ElapsedMilliseconds >= 200, $"Took {watch.ElapsedMilliseconds} ms");
        Assert.Equal("after the wait", Assert.Single(log.Read()).Message);
    }

    [Fact]
    public void A_lock_that_is_never_released_gives_a_clear_error()
    {
        SharedFile.Patience = TimeSpan.FromMilliseconds(200);
        string path = _folder.File("stuck.vault");
        using var vault = CaltropVault.Create(path, _key);
        using var held = new FileStream(path + ".lock", FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);

        IOException ex = Assert.Throws<IOException>(() => vault.Set("a", "1"));

        Assert.Contains("busy", ex.Message, StringComparison.Ordinal);
        Assert.Null(vault.Get("a")); // reading never needs the lock
    }

    [Fact]
    public void A_vault_file_changed_while_open_raises_the_alarm_once()
    {
        string path = _folder.File("changed.vault");
        using var vault = CaltropVault.Create(path, _key);
        vault.Set("a", "1");
        using (var other = CaltropVault.Open(path, _key))
        {
            other.Set("b", "2"); // a newer version, which is then damaged
        }

        byte[] data = File.ReadAllBytes(path);
        data[^1] ^= 1;
        File.WriteAllBytes(path, data);
        using var alarms = new AlarmRecorder();

        TestData.Throws(CaltropErrorCode.AuthenticationFailed, () => vault.Get("a"));
        TestData.Throws(CaltropErrorCode.AuthenticationFailed, () => vault.Get("a"));
        TestData.Throws(CaltropErrorCode.AuthenticationFailed, () => vault.Set("c", "3")); // never saves over it

        Assert.Equal(CaltropAlarmKind.Tampering, Assert.Single(alarms.Alarms).Kind);
        Assert.Equal(data, File.ReadAllBytes(path));
    }
}

/// <summary>Caltrop's own folder: clear errors, and one key even when copies of the app start together.</summary>
[Collection(GlobalState.Name)]
public sealed class HomeStabilityTests : IDisposable
{
    private readonly TempFolder _temp = new();
    private readonly string _folder;

    public HomeStabilityTests()
    {
        GlobalState.Reset();
        _folder = Path.Combine(_temp.Path, "MyApp");
        Caltrop.Folder = _folder;
    }

    public void Dispose()
    {
        GlobalState.Reset();
        _temp.Dispose();
    }

    [Fact]
    public void A_folder_that_cannot_be_made_gives_a_clear_error()
    {
        string notAFolder = Path.Combine(_temp.Path, "a-file");
        File.WriteAllText(notAFolder, "x");
        Caltrop.Folder = Path.Combine(notAFolder, "MyApp");

        InvalidOperationException ex = Assert.Throws<InvalidOperationException>(() => Caltrop.Encrypt("x"));
        Assert.Contains("could not create its folder", ex.Message, StringComparison.Ordinal);
        Assert.Contains(Caltrop.FolderEnvironmentVariable, ex.Message, StringComparison.Ordinal);

        Caltrop.UseKey(CaltropKey.Generate());
        ex = Assert.Throws<InvalidOperationException>(() => Caltrop.Secrets.Set("a", "b"));
        Assert.Contains("could not create its folder", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Making_the_key_leaves_only_the_key_behind()
    {
        Caltrop.Encrypt("x");

        Assert.Equal(["README.txt", "caltrop.key"], Directory.GetFiles(_folder).Select(file => Path.GetFileName(file)).Order(StringComparer.Ordinal));
    }

    [Fact]
    public void A_key_made_by_another_copy_of_the_app_while_waiting_is_used()
    {
        Directory.CreateDirectory(_folder);
        string keyFile = Path.Combine(_folder, "caltrop.key");
        using var theirKey = CaltropKey.Generate();
        var held = new FileStream(keyFile + ".lock", FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        Task otherCopy = Task.Run(async () =>
        {
            await Task.Delay(300);
            await File.WriteAllTextAsync(keyFile, theirKey.Export());
            await held.DisposeAsync();
        });

        string secret = Caltrop.Encrypt("made after waiting");
        otherCopy.GetAwaiter().GetResult();

        Assert.Equal("made after waiting", Caltrop.Decrypt(secret, theirKey));
    }

    [Fact]
    public void Two_copies_of_the_app_share_one_secrets_vault()
    {
        Caltrop.Secrets.Set("from-the-first", "1");
        using var secondCopy = CaltropVault.Open(Path.Combine(_folder, "secrets.vault"), Caltrop.DefaultKeys);

        secondCopy.Set("from-the-second", "2");

        Assert.Equal("2", Caltrop.Secrets.Get("from-the-second"));
        Assert.Equal(["from-the-first", "from-the-second"], Caltrop.Secrets.Names);
    }

    [Fact]
    public void An_alarm_set_off_inside_a_handler_is_recorded_but_does_not_call_the_handlers_again()
    {
        int calls = 0;
        Caltrop.Traps.Alarm += (_, _) =>
        {
            calls++;
            Caltrop.Traps.Trigger("Inner trap");
        };

        Caltrop.Traps.Trigger("Outer trap");

        Assert.Equal(1, calls);
        Assert.Contains("Inner trap", File.ReadAllText(Path.Combine(_folder, "caltrop.log")), StringComparison.Ordinal);
    }

    [Fact]
    public void An_alarm_handler_that_reads_a_tampered_vault_does_not_call_itself_forever()
    {
        Caltrop.Secrets.Set("webhook", "https://example.test/hook");
        GlobalState.Restart();
        string vaultFile = Path.Combine(_folder, "secrets.vault");
        byte[] data = File.ReadAllBytes(vaultFile);
        data[^1] ^= 1;
        File.WriteAllBytes(vaultFile, data);
        int calls = 0;
        Caltrop.Traps.Alarm += (_, _) =>
        {
            calls++;
            _ = Caltrop.Secrets.Get("webhook");
        };

        TestData.Throws(CaltropErrorCode.AuthenticationFailed, () => Caltrop.Secrets.Get("webhook"));

        Assert.Equal(1, calls);
    }

    [Fact]
    public void A_handler_that_reads_a_vault_changed_while_open_gets_the_error_without_another_alarm()
    {
        Caltrop.Secrets.Set("a", "1");
        string vaultFile = Path.Combine(_folder, "secrets.vault");
        using (var otherCopy = CaltropVault.Open(vaultFile, Caltrop.DefaultKeys))
        {
            otherCopy.Set("b", "2"); // a newer version, which is then damaged
        }

        byte[] data = File.ReadAllBytes(vaultFile);
        data[^1] ^= 1;
        File.WriteAllBytes(vaultFile, data);
        Exception? inHandler = null;
        Caltrop.Traps.Alarm += (_, _) =>
        {
            try
            {
                _ = Caltrop.Secrets.Get("a");
            }
            catch (CaltropException ex)
            {
                inHandler = ex;
            }
        };

        TestData.Throws(CaltropErrorCode.AuthenticationFailed, () => Caltrop.Secrets.Get("a"));

        Assert.NotNull(inHandler);
        Assert.Single(File.ReadAllLines(Path.Combine(_folder, "caltrop.log")), line => line.Contains("[Tampering]", StringComparison.Ordinal));
    }

    [Fact]
    public void An_alarm_handler_that_writes_to_a_tampered_log_does_not_call_itself_forever()
    {
        Caltrop.Log("a");
        Caltrop.Log("b");
        GlobalState.Restart();
        string logFile = Path.Combine(_folder, "caltrop.log");
        string[] lines = File.ReadAllLines(logFile);
        lines[1] = lines[1].Replace("\ta\t", "\tz\t", StringComparison.Ordinal);
        File.WriteAllLines(logFile, lines);
        int calls = 0;
        Caltrop.Traps.Alarm += (_, alarm) =>
        {
            calls++;
            Caltrop.Log($"handled: {alarm.Message}");
        };

        Caltrop.Log("c");

        Assert.Equal(1, calls);
        Assert.Contains("\tc\t", File.ReadAllText(logFile), StringComparison.Ordinal);
    }

    [Fact]
    public void Making_a_key_does_not_run_the_self_check_but_using_one_does()
    {
        Caltrop.ResetSelfCheckForTests();
        using var key = CaltropKey.Generate();
        Assert.False(Caltrop.SelfCheckDone);

        Caltrop.Encrypt("x", key);

        Assert.True(Caltrop.SelfCheckDone);
    }
}
