using CaltropSecurity.Internal;

namespace CaltropSecurity.Tests;

[Collection(GlobalState.Name)]
public sealed class StatusTests : IDisposable
{
    private readonly TempFolder _temp = new();
    private readonly string _folder;

    public StatusTests()
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
    public void A_new_app_is_fine_and_nothing_is_made()
    {
        CaltropStatus status = Caltrop.Status();

        Assert.True(status.Ok, status.ToString());
        Assert.Empty(status.Problems);
        Assert.Equal("1.0.0", status.Version);
        Assert.StartsWith("Caltrop 1.0.0: everything is fine.", status.ToString(), StringComparison.Ordinal);
        Assert.Contains("Caltrop makes", status.ToString(), StringComparison.Ordinal);
        Assert.False(Directory.Exists(_folder)); // looking never makes anything
    }

    [Fact]
    public void After_first_use_it_names_the_key_file_to_back_up()
    {
        Caltrop.Encrypt("x");
        Caltrop.Secrets.Set("a", "1");
        Caltrop.Log("hello");

        CaltropStatus status = Caltrop.Status();
        string report = status.ToString();

        Assert.True(status.Ok, report);
        Assert.Contains(Path.Combine(_folder, "caltrop.key") + " (back this file up)", report, StringComparison.Ordinal);
        Assert.Contains("1 secret", report, StringComparison.Ordinal);
        Assert.Contains("1 entry, none changed", report, StringComparison.Ordinal);
        Assert.Contains("no lockdown", report, StringComparison.Ordinal);
    }

    [Fact]
    public void It_says_where_the_key_comes_from()
    {
        Environment.SetEnvironmentVariable(Caltrop.KeyEnvironmentVariable, CaltropKey.Generate().Export());
        Assert.Contains("the CALTROP_KEY environment variable", Caltrop.Status().ToString(), StringComparison.Ordinal);

        Caltrop.UseKey(CaltropKey.Generate());
        Assert.Contains("Caltrop.UseKey", Caltrop.Status().ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void A_broken_key_is_a_problem()
    {
        Environment.SetEnvironmentVariable(Caltrop.KeyEnvironmentVariable, "ctk_not-a-key");

        CaltropStatus status = Caltrop.Status();

        Assert.False(status.Ok);
        Assert.Contains("CALTROP_KEY", Assert.Single(status.Problems), StringComparison.Ordinal);
        Assert.Contains("PROBLEM:", status.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void A_container_with_no_key_is_a_problem()
    {
        Home.ResetForTests();
        Environment.SetEnvironmentVariable("DOTNET_RUNNING_IN_CONTAINER", "true");

        CaltropStatus status = Caltrop.Status();

        Assert.False(status.Ok);
        Assert.Contains("CALTROP_KEY", Assert.Single(status.Problems), StringComparison.Ordinal);
        Assert.Contains("CALTROP_FOLDER", status.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void A_tampered_log_or_vault_is_a_problem()
    {
        Caltrop.Log("a");
        Caltrop.Log("b");
        Caltrop.Secrets.Set("a", "1");
        GlobalState.Restart();
        string logFile = Path.Combine(_folder, "caltrop.log");
        File.WriteAllText(logFile, File.ReadAllText(logFile).Replace("\ta\t", "\tz\t", StringComparison.Ordinal));
        string vaultFile = Path.Combine(_folder, "secrets.vault");
        byte[] vault = File.ReadAllBytes(vaultFile);
        vault[^1] ^= 1;
        File.WriteAllBytes(vaultFile, vault);
        using var alarms = new AlarmRecorder();

        CaltropStatus status = Caltrop.Status();

        Assert.True(status.Problems.Count == 2, status.ToString());
        Assert.Contains(status.Problems, problem => problem.Contains("tampered with", StringComparison.Ordinal) && problem.Contains("caltrop.log", StringComparison.Ordinal));
        Assert.Contains(status.Problems, problem => problem.Contains("secrets.vault", StringComparison.Ordinal));
        Assert.Contains(alarms.Alarms, alarm => alarm.Kind == CaltropAlarmKind.Tampering && alarm.Message.Contains("log", StringComparison.Ordinal));
        Assert.Contains(alarms.Alarms, alarm => alarm.Kind == CaltropAlarmKind.Tampering && alarm.Message.Contains("vault", StringComparison.Ordinal));
    }

    [Fact]
    public void A_lockdown_is_a_problem()
    {
        Caltrop.Traps.LockDown("testing");

        CaltropStatus status = Caltrop.Status();

        Assert.False(status.Ok);
        Assert.Contains("Restart the app", Assert.Single(status.Problems), StringComparison.Ordinal);
        Assert.Contains("  Lockdown", status.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void It_lists_the_trap_settings()
    {
        Caltrop.Traps.LockDownOn = CaltropAlarmKind.DecoyUsed;
        Caltrop.Traps.Alarm += (_, _) => { };

        string report = Caltrop.Status().ToString();

        Assert.Contains("1 alarm handler", report, StringComparison.Ordinal);
        Assert.Contains("lockdown on DecoyUsed", report, StringComparison.Ordinal);
    }
}
