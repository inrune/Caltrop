using System.Text;

namespace CaltropSecurity.Tests;

public sealed class VaultTests : IDisposable
{
    private const string Password = "a long vault password 2026";
    private readonly TempFolder _folder = new();

    public void Dispose() => _folder.Dispose();

    [Fact]
    public void Secrets_survive_closing_and_reopening()
    {
        string path = _folder.File("secrets.vault");
        using (var vault = CaltropVault.Create(path, Password))
        {
            vault.Set("db-password", "hunter2");
            vault.Set("binary", [0, 1, 2, 255]);
            vault.Set("emoji", "🔐 ünïcödé");
        }

        using var opened = CaltropVault.Open(path, Password);

        Assert.Equal("hunter2", opened.Get("db-password"));
        Assert.Equal(new byte[] { 0, 1, 2, 255 }, opened.GetBytes("binary"));
        Assert.Equal("🔐 ünïcödé", opened.Get("emoji"));
        Assert.Equal(["binary", "db-password", "emoji"], opened.Names);
        Assert.Equal(3, opened.Count);
        Assert.Null(opened.Get("missing"));
    }

    [Fact]
    public void Set_replaces_and_Remove_deletes_and_both_are_saved()
    {
        string path = _folder.File("v.vault");
        using (var vault = CaltropVault.Create(path, Password))
        {
            vault.Set("a", "1");
            vault.Set("a", "2");
            vault.Set("b", "x");
            Assert.True(vault.Remove("b"));
            Assert.False(vault.Remove("b"));
        }

        using var opened = CaltropVault.Open(path, Password);
        Assert.Equal("2", opened.Get("a"));
        Assert.False(opened.Contains("b"));
    }

    [Fact]
    public void The_file_never_contains_the_secrets_in_plain_text()
    {
        string path = _folder.File("v.vault");
        using (var vault = CaltropVault.Create(path, Password))
        {
            vault.Set("api-key", "sk_live_SUPERSECRET");
        }

        string raw = Encoding.Latin1.GetString(File.ReadAllBytes(path));
        Assert.DoesNotContain("SUPERSECRET", raw);
        Assert.DoesNotContain("api-key", raw);
        Assert.Empty(Directory.GetFiles(_folder.Path, "*.tmp"));
    }

    [Fact]
    public void A_wrong_password_and_a_changed_file_give_the_same_error()
    {
        string path = _folder.File("v.vault");
        using (var vault = CaltropVault.Create(path, Password))
        {
            vault.Set("x", "y");
        }

        CaltropException wrong = TestData.Throws(CaltropErrorCode.AuthenticationFailed, () => CaltropVault.Open(path, "wrong password"));

        byte[] data = File.ReadAllBytes(path);
        File.WriteAllBytes(path, TestData.FlipBit(data, data.Length - 20));
        CaltropException changed = TestData.Throws(CaltropErrorCode.AuthenticationFailed, () => CaltropVault.Open(path, Password));
        Assert.Equal(wrong.Message, changed.Message);
    }

    [Fact]
    public void ChangePassword_switches_to_the_new_password()
    {
        string path = _folder.File("v.vault");
        using (var vault = CaltropVault.Create(path, Password))
        {
            vault.Set("x", "y");
            vault.ChangePassword("a brand new password");
        }

        TestData.Throws(CaltropErrorCode.AuthenticationFailed, () => CaltropVault.Open(path, Password));
        using var opened = CaltropVault.Open(path, "a brand new password");
        Assert.Equal("y", opened.Get("x"));
    }

    [Fact]
    public void A_key_vault_opens_only_with_its_key()
    {
        string path = _folder.File("k.vault");
        using var key = CaltropKey.Generate();
        using (var vault = CaltropVault.Create(path, key))
        {
            vault.Set("token", "abc");
            Assert.Throws<InvalidOperationException>(() => vault.ChangePassword("nope nope nope"));
        }

        using (var opened = CaltropVault.Open(path, key))
        {
            Assert.Equal("abc", opened.Get("token"));
        }

        using var other = CaltropKey.Generate();
        TestData.Throws(CaltropErrorCode.KeyMismatch, () => CaltropVault.Open(path, other));
        TestData.Throws(CaltropErrorCode.WrongDataType, () => CaltropVault.Open(path, Password));
    }

    [Fact]
    public void Create_refuses_to_overwrite_and_Open_needs_a_file()
    {
        string path = _folder.File("v.vault");
        CaltropVault.Create(path, Password).Dispose();

        Assert.Throws<IOException>(() => CaltropVault.Create(path, Password));
        Assert.Throws<FileNotFoundException>(() => CaltropVault.Open(_folder.File("missing.vault"), Password));
    }

    [Fact]
    public void A_disposed_vault_cannot_be_used()
    {
        var vault = CaltropVault.Create(_folder.File("v.vault"), Password);
        vault.Set("x", "y");

        vault.Dispose();

        Assert.Throws<ObjectDisposedException>(() => vault.Get("x"));
        Assert.Throws<ObjectDisposedException>(() => vault.Set("x", "z"));
    }

    [Fact]
    public void Names_are_checked()
    {
        using var vault = CaltropVault.Create(_folder.File("v.vault"), Password);

        Assert.Throws<ArgumentException>(() => vault.Set("", "x"));
        Assert.Throws<ArgumentException>(() => vault.Set(new string('n', 257), "x"));
    }
}

[Collection(GlobalState.Name)]
public sealed class VaultAlarmTests : IDisposable
{
    private readonly TempFolder _folder = new();

    public VaultAlarmTests() => GlobalState.Reset();

    public void Dispose()
    {
        _folder.Dispose();
        GlobalState.Reset();
    }

    [Fact]
    public void A_changed_key_vault_raises_a_tampering_alarm()
    {
        string path = _folder.File("k.vault");
        using var key = CaltropKey.Generate();
        CaltropVault.Create(path, key).Dispose();
        byte[] data = File.ReadAllBytes(path);
        File.WriteAllBytes(path, TestData.FlipBit(data, data.Length - 1));
        using var alarms = new AlarmRecorder();

        TestData.Throws(CaltropErrorCode.AuthenticationFailed, () => CaltropVault.Open(path, key));

        Assert.Equal(CaltropAlarmKind.Tampering, Assert.Single(alarms.Alarms).Kind);
    }

    [Fact]
    public void A_lockdown_wipes_open_vaults()
    {
        using var vault = CaltropVault.Create(_folder.File("v.vault"), "a long vault password 2026");
        vault.Set("x", "y");

        Caltrop.Traps.LockDown("Test");

        TestData.Throws(CaltropErrorCode.LockedDown, () => vault.Get("x"));
    }
}
