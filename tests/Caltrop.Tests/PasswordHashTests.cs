namespace CaltropSecurity.Tests;

public class PasswordHashTests
{
    [Fact]
    public void Hash_uses_the_PHC_format_with_600000_iterations()
    {
        string hash = Caltrop.Passwords.Hash("hunter2");

        Assert.Matches(@"^\$pbkdf2-sha256\$i=600000\$[A-Za-z0-9+/]{22}\$[A-Za-z0-9+/]{43}$", hash);
        Assert.True(Caltrop.Passwords.Verify("hunter2", hash));
        Assert.False(Caltrop.Passwords.Verify("hunter3", hash));
        Assert.False(Caltrop.Passwords.NeedsRehash(hash));
    }

    [Fact]
    public void The_same_password_gives_different_hashes()
    {
        Assert.NotEqual(Caltrop.Passwords.Hash("same", 1000), Caltrop.Passwords.Hash("same", 1000));
    }

    [Fact]
    public void Verifies_standard_PBKDF2_hashes_made_by_other_tools()
    {
        // Made with Python: hashlib.pbkdf2_hmac("sha256", password, b"caltrop-test-salt", 1000, 32)
        const string hash = "$pbkdf2-sha256$i=1000$Y2FsdHJvcC10ZXN0LXNhbHQ$FPfMlXhM0qYeOBxdxZtMYU3S0Yq/qRT7XiwZVkDEszk";

        Assert.True(Caltrop.Passwords.Verify("correct horse battery staple", hash));
        Assert.False(Caltrop.Passwords.Verify("correct horse battery stapler", hash));
        Assert.True(Caltrop.Passwords.NeedsRehash(hash));
    }

    [Fact]
    public void Hashes_with_old_settings_need_rehashing()
    {
        Assert.True(Caltrop.Passwords.NeedsRehash(Caltrop.Passwords.Hash("pw", 1000)));
        Assert.True(Caltrop.Passwords.NeedsRehash("not a hash"));
    }

    [Fact]
    public void Unicode_passwords_match_however_they_were_typed()
    {
        string precomposed = "café";   // é as one character
        string decomposed = "café";   // e followed by a combining accent

        string hash = Caltrop.Passwords.Hash(precomposed, 1000);

        Assert.True(Caltrop.Passwords.Verify(decomposed, hash));
    }

    [Fact]
    public void Swapped_arguments_give_a_helpful_error()
    {
        string hash = Caltrop.Passwords.Hash("pw", 1000);

        CaltropException ex = TestData.Throws(CaltropErrorCode.InvalidFormat, () => Caltrop.Passwords.Verify(hash, "pw"));
        Assert.Contains("Verify(password, hash)", ex.Message);
    }

    [Theory]
    [InlineData("$pbkdf2-sha256$i=0$Y2FsdHJvcC10ZXN0LXNhbHQ$FPfMlXhM0qYeOBxdxZtMYU3S0Yq/qRT7XiwZVkDEszk")]
    [InlineData("$pbkdf2-sha256$i=-5$Y2FsdHJvcC10ZXN0LXNhbHQ$FPfMlXhM0qYeOBxdxZtMYU3S0Yq/qRT7XiwZVkDEszk")]
    [InlineData("$pbkdf2-sha256$i=99999999999$Y2FsdHJvcC10ZXN0LXNhbHQ$FPfMlXhM0qYeOBxdxZtMYU3S0Yq/qRT7XiwZVkDEszk")]
    [InlineData("$pbkdf2-sha512$i=1000$Y2FsdHJvcC10ZXN0LXNhbHQ$FPfMlXhM0qYeOBxdxZtMYU3S0Yq/qRT7XiwZVkDEszk")]
    [InlineData("$pbkdf2-sha256$i=1000$c2FsdA$FPfMlXhM0qYeOBxdxZtMYU3S0Yq/qRT7XiwZVkDEszk")]
    [InlineData("$pbkdf2-sha256$i=1000$Y2FsdHJvcC10ZXN0LXNhbHQ$!!!")]
    [InlineData("$2b$12$abcdefghijklmnopqrstuuWIbYSr4TFa4c.zf2lRo0RdgP6tqyVym")]
    public void Malformed_or_foreign_hashes_are_rejected(string hash)
    {
        TestData.Throws(CaltropErrorCode.InvalidFormat, () => Caltrop.Passwords.Verify("pw", hash));
    }

    [Fact]
    public void Empty_passwords_cannot_be_hashed()
    {
        Assert.Throws<ArgumentException>(() => Caltrop.Passwords.Hash(""));
        Assert.Throws<ArgumentNullException>(() => Caltrop.Passwords.Hash(null!));
    }
}
