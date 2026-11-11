namespace CaltropSecurity.Tests;

/// <summary>
/// These tests change process-wide state (the default key and the CALTROP_KEY environment variable). They all live
/// in this one class, so xUnit runs them one after another, and no other test uses the default key.
/// </summary>
public sealed class DefaultKeyTests : IDisposable
{
    public DefaultKeyTests() => Reset();

    public void Dispose() => Reset();

    [Fact]
    public void Without_a_key_the_error_says_how_to_set_one()
    {
        InvalidOperationException ex = Assert.Throws<InvalidOperationException>(() => Caltrop.Encrypt("x"));

        Assert.Contains("CALTROP_KEY", ex.Message);
        Assert.Contains("Caltrop.UseKey", ex.Message);
    }

    [Fact]
    public void UseKey_sets_the_default_key()
    {
        using var key = CaltropKey.Generate();
        Caltrop.UseKey(key);

        string encrypted = Caltrop.Encrypt("hello");

        Assert.Equal("hello", Caltrop.Decrypt(encrypted));
        Assert.Equal("hello", Caltrop.Decrypt(encrypted, key));
        Assert.Equal(new byte[] { 1, 2, 3 }, Caltrop.Decrypt(Caltrop.Encrypt(new byte[] { 1, 2, 3 })));
    }

    [Fact]
    public void The_key_is_read_from_CALTROP_KEY()
    {
        using var key = CaltropKey.Generate();
        Environment.SetEnvironmentVariable(Caltrop.KeyEnvironmentVariable, key.Export());

        string encrypted = Caltrop.Encrypt("from the environment");

        Assert.Equal("from the environment", Caltrop.Decrypt(encrypted, key));
        Assert.Equal(key.Id, Caltrop.DefaultKeys.Primary.Id);
    }

    [Fact]
    public void CALTROP_KEY_can_hold_several_keys_for_rotation()
    {
        using var newKey = CaltropKey.Generate();
        using var oldKey = CaltropKey.Generate();
        string oldData = Caltrop.Encrypt("old", oldKey);
        Environment.SetEnvironmentVariable(Caltrop.KeyEnvironmentVariable, $"{newKey.Export()},{oldKey.Export()}");

        Assert.Equal("old", Caltrop.Decrypt(oldData));
        Assert.Equal("new", Caltrop.Decrypt(Caltrop.Encrypt("new"), newKey));
    }

    [Fact]
    public void An_invalid_CALTROP_KEY_gives_a_clear_error()
    {
        Environment.SetEnvironmentVariable(Caltrop.KeyEnvironmentVariable, "not-a-key");

        CaltropException ex = TestData.Throws(CaltropErrorCode.InvalidKey, () => Caltrop.Encrypt("x"));
        Assert.Contains("CALTROP_KEY", ex.Message);
    }

    [Fact]
    public void Tokens_use_the_default_keys()
    {
        using var key = CaltropKey.Generate();
        Caltrop.UseKeys(new CaltropKeyRing(key));

        string token = Caltrop.Tokens.Create("user-1", TimeSpan.FromMinutes(10), purpose: "login");

        Assert.Equal("user-1", Caltrop.Tokens.Validate(token, purpose: "login"));
        Assert.True(Caltrop.Tokens.TryValidate(token, out string? payload, purpose: "login"));
        Assert.Equal("user-1", payload);
        Assert.False(Caltrop.Tokens.TryValidate(token, out _));
    }

    [Fact]
    public void UseKey_rejects_null()
    {
        Assert.Throws<ArgumentNullException>(() => Caltrop.UseKey(null!));
        Assert.Throws<ArgumentNullException>(() => Caltrop.UseKeys(null!));
    }

    private static void Reset()
    {
        Environment.SetEnvironmentVariable(Caltrop.KeyEnvironmentVariable, null);
        Caltrop.ResetDefaultKeys();
    }
}
