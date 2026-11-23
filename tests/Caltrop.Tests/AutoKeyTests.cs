using CaltropSecurity.Internal;

namespace CaltropSecurity.Tests;

/// <summary>Caltrop makes and keeps its own key, so apps need no setup.</summary>
[Collection(GlobalState.Name)]
public sealed class AutoKeyTests : IDisposable
{
    private readonly TempFolder _temp = new();
    private readonly string _folder;

    public AutoKeyTests()
    {
        GlobalState.Reset();
        _folder = Path.Combine(_temp.Path, "MyApp"); // does not exist yet: Caltrop creates it
        Caltrop.Folder = _folder;
    }

    private string KeyFile => Path.Combine(_folder, "caltrop.key");

    public void Dispose()
    {
        GlobalState.Reset();
        _temp.Dispose();
    }

    [Fact]
    public void Encrypt_works_with_no_setup_at_all()
    {
        string secret = Caltrop.Encrypt("hello");

        Assert.Equal("hello", Caltrop.Decrypt(secret));
        Assert.StartsWith("ctk_", File.ReadAllText(KeyFile).Trim());
        Assert.Contains("back it up", File.ReadAllText(Path.Combine(_folder, "README.txt")));
    }

    [Fact]
    public void The_key_file_and_folder_are_private_to_the_user()
    {
        Caltrop.Encrypt("x");

        if (OperatingSystem.IsWindows())
        {
            Assert.Skip("Windows protects the user's app data folder with its own permissions.");
        }
        else
        {
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(KeyFile));
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute, File.GetUnixFileMode(_folder));
        }
    }

    [Fact]
    public void The_same_key_is_used_after_a_restart()
    {
        string secret = Caltrop.Encrypt("kept");

        GlobalState.Restart();

        Assert.Equal("kept", Caltrop.Decrypt(secret));
    }

    [Fact]
    public void CALTROP_KEY_and_UseKey_come_before_the_key_file()
    {
        Caltrop.Encrypt("makes the key file");
        string fileKey = Caltrop.DefaultKeys.Primary.Id;
        GlobalState.Restart();

        using var environmentKey = CaltropKey.Generate();
        Environment.SetEnvironmentVariable(Caltrop.KeyEnvironmentVariable, environmentKey.Export());
        Assert.Equal(environmentKey.Id, Caltrop.DefaultKeys.Primary.Id);

        using var codeKey = CaltropKey.Generate();
        Caltrop.UseKey(codeKey);
        Assert.Equal(codeKey.Id, Caltrop.DefaultKeys.Primary.Id);
        Assert.NotEqual(fileKey, codeKey.Id);
    }

    [Fact]
    public void With_no_folder_and_no_key_the_error_says_what_to_do()
    {
        Caltrop.Folder = null;

        InvalidOperationException ex = Assert.Throws<InvalidOperationException>(() => Caltrop.Encrypt("x"));

        Assert.Contains("CALTROP_KEY", ex.Message);
    }

    [Fact]
    public void In_a_container_Caltrop_never_makes_a_key_that_would_be_thrown_away()
    {
        Home.ResetForTests(); // back to the default folder rules
        Environment.SetEnvironmentVariable("DOTNET_RUNNING_IN_CONTAINER", "true");

        Assert.Null(Caltrop.Folder);
        InvalidOperationException ex = Assert.Throws<InvalidOperationException>(() => Caltrop.Encrypt("x"));
        Assert.Contains("container", ex.Message);

        Environment.SetEnvironmentVariable(Caltrop.FolderEnvironmentVariable, _folder);
        Assert.Equal(Path.GetFullPath(_folder), Caltrop.Folder);
        Assert.Equal("ok", Caltrop.Decrypt(Caltrop.Encrypt("ok")));
    }

    [Fact]
    public void A_damaged_key_file_is_never_replaced()
    {
        Directory.CreateDirectory(_folder);
        File.WriteAllText(KeyFile, "ctk_damaged");

        CaltropException ex = TestData.Throws(CaltropErrorCode.InvalidKey, () => Caltrop.Encrypt("x"));

        Assert.Contains("backup", ex.Message);
        Assert.Equal("ctk_damaged", File.ReadAllText(KeyFile));
    }

    [Fact]
    public void The_key_file_can_hold_an_old_key_for_rotation()
    {
        using var oldKey = CaltropKey.Generate();
        using var newKey = CaltropKey.Generate();
        string oldData = Caltrop.Encrypt("old", oldKey);
        Directory.CreateDirectory(_folder);
        File.WriteAllText(KeyFile, $"{newKey.Export()},{oldKey.Export()}");

        Assert.Equal("old", Caltrop.Decrypt(oldData));
        Assert.Equal(newKey.Id, Caltrop.DefaultKeys.Primary.Id);
    }

    [Fact]
    public void Changing_the_folder_switches_to_that_folders_key()
    {
        Caltrop.Encrypt("a");
        string first = Caltrop.DefaultKeys.Primary.Id;

        Caltrop.Folder = Path.Combine(_temp.Path, "Other");

        Caltrop.Encrypt("b");
        Assert.NotEqual(first, Caltrop.DefaultKeys.Primary.Id);
    }

    [Fact]
    public void Threads_starting_at_once_all_get_the_same_key()
    {
        string[] ids = new string[16];

        Parallel.For(0, ids.Length, i => ids[i] = Caltrop.DefaultKeys.Primary.Id);

        Assert.Single(ids.Distinct());
        Assert.Single(Directory.GetFiles(_folder, "caltrop.key*"));
    }

    [Fact]
    public void Decoys_are_recognized_after_a_restart_with_no_setup()
    {
        string decoy = Caltrop.Decoys.PasswordHash();
        GlobalState.Restart();
        using var alarms = new AlarmRecorder();

        Assert.False(Caltrop.Passwords.Verify("admin", decoy));

        Assert.Equal(CaltropAlarmKind.DecoyUsed, Assert.Single(alarms.Alarms).Kind);
    }

    [Fact]
    public void Checking_a_password_never_creates_a_key_file()
    {
        Caltrop.Passwords.Verify("x", Caltrop.Passwords.Hash("a password here"));
        Caltrop.ApiKeys.IsWellFormed(Caltrop.ApiKeys.Generate("acme"));

        Assert.False(File.Exists(KeyFile));
    }
}
