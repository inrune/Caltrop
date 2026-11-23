using System.Text;
using CaltropSecurity.Internal;

namespace CaltropSecurity.Tests;

/// <summary>Caltrop.Secrets and Caltrop.Log: nothing to set up.</summary>
[Collection(GlobalState.Name)]
public sealed class SecretsAndLogTests : IDisposable
{
    private readonly TempFolder _temp = new();
    private readonly string _folder;

    public SecretsAndLogTests()
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
    public void Secrets_are_kept_encrypted_with_no_setup()
    {
        Caltrop.Secrets.Set("db-password", "hunter2");
        Caltrop.Secrets.Set("blob", [1, 2, 3]);

        Assert.Equal("hunter2", Caltrop.Secrets.Get("db-password"));
        Assert.Equal(new byte[] { 1, 2, 3 }, Caltrop.Secrets.GetBytes("blob"));
        Assert.True(Caltrop.Secrets.Contains("db-password"));
        Assert.Equal(["blob", "db-password"], Caltrop.Secrets.Names);
        Assert.True(Caltrop.Secrets.Remove("blob"));
        Assert.Null(Caltrop.Secrets.Get("blob"));

        string raw = Encoding.Latin1.GetString(File.ReadAllBytes(Path.Combine(_folder, "secrets.vault")));
        Assert.DoesNotContain("hunter2", raw);
    }

    [Fact]
    public void Secrets_survive_a_restart()
    {
        Caltrop.Secrets.Set("api-key", "sk_live_123");

        GlobalState.Restart();

        Assert.Equal("sk_live_123", Caltrop.Secrets.Get("api-key"));
    }

    [Fact]
    public void A_lockdown_wipes_the_secrets()
    {
        Caltrop.Secrets.Set("x", "y");

        Caltrop.Traps.LockDown("Test");

        TestData.Throws(CaltropErrorCode.LockedDown, () => Caltrop.Secrets.Get("x"));
    }

    [Fact]
    public void Log_writes_to_Caltrops_own_tamper_proof_log()
    {
        Caltrop.Log("alice logged in");
        Caltrop.Log("alice changed her password");

        CaltropLogCheck check = Caltrop.CheckLog();

        Assert.True(check.IsIntact, check.Problem);
        Assert.Equal(2, check.Entries);
        GlobalState.Restart();
        Assert.Contains("alice changed her password", File.ReadAllText(Path.Combine(_folder, "caltrop.log")));
    }

    [Fact]
    public void Alarms_are_recorded_in_Caltrops_log_automatically()
    {
        Caltrop.Traps.Trigger("Fake admin page", "203.0.113.7");

        GlobalState.Restart();

        string log = File.ReadAllText(Path.Combine(_folder, "caltrop.log"));
        Assert.Contains("Fake admin page", log);
        Assert.Contains("203.0.113.7", log);
    }

    [Fact]
    public void Tampering_with_Caltrops_log_is_found()
    {
        Caltrop.Log("amount=10");
        Caltrop.Log("amount=20");
        GlobalState.Restart();
        string path = Path.Combine(_folder, "caltrop.log");
        File.WriteAllText(path, File.ReadAllText(path).Replace("amount=10", "amount=99", StringComparison.Ordinal));
        using var alarms = new AlarmRecorder();

        Assert.False(Caltrop.CheckLog().IsIntact);
        Assert.Contains(alarms.Alarms, alarm => alarm.Kind == CaltropAlarmKind.Tampering);
    }

    [Fact]
    public void Without_a_folder_secrets_and_the_log_say_what_to_do()
    {
        using var key = CaltropKey.Generate();
        Caltrop.UseKey(key);
        Caltrop.Folder = null;

        InvalidOperationException ex = Assert.Throws<InvalidOperationException>(() => Caltrop.Secrets.Set("x", "y"));
        Assert.Contains("CALTROP_FOLDER", ex.Message);
        Assert.Throws<InvalidOperationException>(() => Caltrop.Log("x"));
        Caltrop.Traps.Trigger("Still raised without a folder"); // never throws
    }
}

/// <summary>Caltrop.Passwords.Create and LogIn: user passwords from start to finish.</summary>
[Collection(GlobalState.Name)]
public sealed class PasswordLoginTests : IDisposable
{
    private const string Strong = "violet-anchor-pepper-glacier";

    public PasswordLoginTests()
    {
        GlobalState.Reset();
        Caltrop.Passwords.Lockout = new CaltropLockout { SlowDown = false };
    }

    public void Dispose() => GlobalState.Reset();

    [Fact]
    public void Create_refuses_weak_passwords_and_says_why()
    {
        CaltropNewPassword result = Caltrop.Passwords.Create("password1");

        Assert.False(result.Ok);
        Assert.Null(result.Hash);
        Assert.Contains("most common", result.Message);
    }

    [Fact]
    public void Create_hashes_strong_passwords()
    {
        CaltropNewPassword result = Caltrop.Passwords.Create(Strong, "Alice", "alice@example.com");

        Assert.True(result.Ok, result.Message);
        Assert.Equal(string.Empty, result.Message);
        Assert.True(Caltrop.Passwords.Verify(Strong, result.Hash!));
        Assert.Equal("Very strong", result.Strength);
    }

    [Fact]
    public void Create_refuses_the_users_own_name()
    {
        Assert.False(Caltrop.Passwords.Create("alice-rocks-2026-forever", "Alice").Ok);
    }

    [Fact]
    public void Create_follows_the_apps_rules()
    {
        Caltrop.Passwords.Rules = new CaltropPasswordRules { MinLength = 6, MinScore = 0, BlockCommon = false };

        Assert.True(Caltrop.Passwords.Create("dragon").Ok);
    }

    [Fact]
    public void LogIn_lets_the_right_password_in()
    {
        string hash = Caltrop.Passwords.Create(Strong).Hash!;

        CaltropLogin login = Caltrop.Passwords.LogIn("alice", Strong, hash);

        Assert.True(login.Ok);
        Assert.Equal("Logged in.", login.Message);
        Assert.Null(login.NewHash);
    }

    [Fact]
    public void A_wrong_password_and_an_unknown_user_get_the_same_answer()
    {
        string hash = Caltrop.Passwords.Create(Strong).Hash!;

        CaltropLogin wrong = Caltrop.Passwords.LogIn("alice", "wrong password", hash);
        CaltropLogin unknown = Caltrop.Passwords.LogIn("nobody", Strong, storedHash: null);

        Assert.False(wrong.Ok);
        Assert.False(unknown.Ok);
        Assert.Equal("Wrong user name or password.", wrong.Message);
        Assert.Equal(wrong.Message, unknown.Message);
    }

    [Fact]
    public void LogIn_locks_out_after_too_many_failures_even_for_the_right_password()
    {
        string hash = Caltrop.Passwords.Create(Strong).Hash!;
        for (int i = 0; i < 5; i++)
        {
            Caltrop.Passwords.LogIn("alice@example.com", "guess " + i, hash);
        }

        CaltropLogin login = Caltrop.Passwords.LogIn("ALICE@example.com", Strong, hash);

        Assert.False(login.Ok);
        Assert.True(login.LockedOut);
        Assert.Equal("Too many attempts. Try again in 15 minutes.", login.Message);
    }

    [Fact]
    public void LogIn_upgrades_old_hashes()
    {
        byte[] salt = TestData.RandomBytes(16);
        byte[] derived = new byte[32];
        PasswordKdf.Derive(Strong, salt, 100_000, derived);
        string oldHash = Caltrop.Passwords.Format(100_000, salt, derived);

        CaltropLogin login = Caltrop.Passwords.LogIn("bob", Strong, oldHash);

        Assert.True(login.Ok);
        Assert.NotNull(login.NewHash);
        Assert.False(Caltrop.Passwords.NeedsRehash(login.NewHash!));
        Assert.True(Caltrop.Passwords.Verify(Strong, login.NewHash!));
    }

    [Fact]
    public void LogIn_to_a_decoy_account_sets_off_the_alarm()
    {
        string decoy = Caltrop.Decoys.PasswordHash();
        using var alarms = new AlarmRecorder();

        CaltropLogin login = Caltrop.Passwords.LogIn("admin", "admin", decoy);

        Assert.False(login.Ok);
        Assert.Contains(alarms.Alarms, alarm => alarm.Kind == CaltropAlarmKind.DecoyUsed);
    }

    [Fact]
    public async Task LogInAsync_works_the_same()
    {
        string hash = Caltrop.Passwords.Create(Strong).Hash!;

        Assert.True((await Caltrop.Passwords.LogInAsync("carol", Strong, hash)).Ok);
        Assert.False((await Caltrop.Passwords.LogInAsync("carol", "wrong", hash)).Ok);
    }

    [Fact]
    public void An_unknown_user_takes_as_long_as_a_real_one()
    {
        string hash = Caltrop.Passwords.Create(Strong).Hash!;
        Caltrop.Passwords.LogIn("warm-up", "x", null);

        var clock = System.Diagnostics.Stopwatch.StartNew();
        Caltrop.Passwords.LogIn("dave", "wrong", hash);
        TimeSpan real = clock.Elapsed;
        clock.Restart();
        Caltrop.Passwords.LogIn("nobody-here", "wrong", null);
        TimeSpan unknown = clock.Elapsed;

        Assert.True(unknown > real / 3, $"unknown {unknown.TotalMilliseconds} ms vs real {real.TotalMilliseconds} ms");
    }
}
