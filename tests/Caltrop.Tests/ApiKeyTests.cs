namespace CaltropSecurity.Tests;

public class ApiKeyTests
{
    [Fact]
    public void Generated_keys_have_the_prefix_and_pass_the_format_check()
    {
        string key = Caltrop.ApiKeys.Generate("acme");

        Assert.Matches("^acme_[0-9A-Za-z]{38}$", key);
        Assert.True(Caltrop.ApiKeys.IsWellFormed(key));
        Assert.True(Caltrop.ApiKeys.IsWellFormed(key, "acme"));
        Assert.False(Caltrop.ApiKeys.IsWellFormed(key, "other"));
    }

    [Fact]
    public void Prefixes_may_contain_underscores()
    {
        string key = Caltrop.ApiKeys.Generate("acme_live");

        Assert.StartsWith("acme_live_", key);
        Assert.True(Caltrop.ApiKeys.IsWellFormed(key, "acme_live"));
        Assert.False(Caltrop.ApiKeys.IsWellFormed(key, "acme"));
    }

    [Fact]
    public void A_typo_fails_the_checksum()
    {
        string key = Caltrop.ApiKeys.Generate("acme");

        for (int i = 5; i < key.Length; i++)
        {
            char[] chars = key.ToCharArray();
            chars[i] = chars[i] == 'x' ? 'y' : 'x';
            Assert.False(Caltrop.ApiKeys.IsWellFormed(new string(chars)));
        }
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("acme")]
    [InlineData("acme_")]
    [InlineData("_0123456789012345678901234567890123456789")]
    [InlineData("acme_tooShort")]
    [InlineData("acme_!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")]
    public void Junk_is_not_well_formed(string? value)
    {
        Assert.False(Caltrop.ApiKeys.IsWellFormed(value));
    }

    [Fact]
    public void Keys_are_unique()
    {
        string[] keys = [.. Enumerable.Range(0, 100).Select(_ => Caltrop.ApiKeys.Generate("k"))];

        Assert.Distinct(keys);
    }

    [Fact]
    public void Hash_is_stable_and_Verify_checks_it()
    {
        string key = Caltrop.ApiKeys.Generate("acme");
        string hash = Caltrop.ApiKeys.Hash(key);

        Assert.Matches("^[0-9a-f]{64}$", hash);
        Assert.Equal(hash, Caltrop.ApiKeys.Hash(key));
        Assert.True(Caltrop.ApiKeys.Verify(key, hash));
        Assert.True(Caltrop.ApiKeys.Verify(key, hash.ToUpperInvariant()));
        Assert.False(Caltrop.ApiKeys.Verify(Caltrop.ApiKeys.Generate("acme"), hash));
        Assert.False(Caltrop.ApiKeys.Verify(null, hash));
    }

    [Fact]
    public void Verify_rejects_a_stored_value_that_is_not_a_hash()
    {
        Assert.Throws<ArgumentException>(() => Caltrop.ApiKeys.Verify("acme_x", "not-a-hash"));
    }

    [Theory]
    [InlineData("")]
    [InlineData("1acme")]
    [InlineData("acme_")]
    [InlineData("ac-me")]
    [InlineData("ac me")]
    [InlineData("abcdefghijklmnopqrstuvwxyzabcdefg")]
    public void Invalid_prefixes_are_rejected(string prefix)
    {
        Assert.Throws<ArgumentException>(() => Caltrop.ApiKeys.Generate(prefix));
    }
}
