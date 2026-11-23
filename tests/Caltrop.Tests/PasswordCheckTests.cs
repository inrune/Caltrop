namespace CaltropSecurity.Tests;

public class PasswordCheckTests
{
    [Theory]
    [InlineData("password")]
    [InlineData("Password123!")]
    [InlineData("P@ssw0rd")]
    [InlineData("qwerty123")]
    [InlineData("iloveyou")]
    [InlineData("123456789012")]
    [InlineData("letmein2026!!")]
    public void Common_passwords_and_their_look_alikes_are_rejected(string password)
    {
        CaltropPasswordCheck check = Caltrop.Passwords.Check(password);

        Assert.False(check.Ok);
        Assert.True(check.Score <= 1, $"score {check.Score} for {password}");
    }

    [Fact]
    public void A_common_password_is_named_as_common()
    {
        CaltropPasswordCheck check = Caltrop.Passwords.Check("sunshine");

        Assert.Equal(0, check.Score);
        Assert.Contains(check.Problems, problem => problem.Contains("most common", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("correct horse battery staple")]
    [InlineData("Gx7#qL9!vR2$mZ4p")]
    [InlineData("purple-otter-tuesday-canyon")]
    public void Strong_passwords_pass(string password)
    {
        CaltropPasswordCheck check = Caltrop.Passwords.Check(password);

        Assert.True(check.Ok, check.ToString());
        Assert.Empty(check.Problems);
        Assert.True(check.Score >= 3);
    }

    [Theory]
    [InlineData("aaaaaaaaaaaaaaaa")]
    [InlineData("abcdefghijklmnop")]
    [InlineData("qwertyuiopasdfgh")]
    [InlineData("abcabcabcabcabc1")]
    [InlineData("1234567890987654")]
    public void Repeats_sequences_and_keyboard_runs_are_weak(string password)
    {
        CaltropPasswordCheck check = Caltrop.Passwords.Check(password);

        Assert.False(check.Ok);
        Assert.True(check.Score <= 2, $"score {check.Score} for {password}");
    }

    [Fact]
    public void Short_passwords_are_rejected_with_a_clear_reason()
    {
        CaltropPasswordCheck check = Caltrop.Passwords.Check("Gx7#qL9!");

        Assert.False(check.Ok);
        Assert.Contains("Use at least 12 characters.", check.Problems);
    }

    [Fact]
    public void The_users_own_name_and_email_are_not_allowed()
    {
        CaltropPasswordCheck check = Caltrop.Passwords.Check("AliceSmith-rocks-2026!", "Alice Smith", "alice.smith@example.com");

        Assert.False(check.Ok);
        Assert.Contains(check.Problems, problem => problem.Contains("your name", StringComparison.Ordinal));
        Assert.True(Caltrop.Passwords.Check("Gx7#qL9!vR2$mZ4p", "Alice Smith").Ok);
    }

    [Fact]
    public void Look_alike_spellings_of_the_users_name_are_caught()
    {
        Assert.False(Caltrop.Passwords.Check("m4ll0ry-is-the-best-99", "Mallory").Ok);
    }

    [Fact]
    public void Rules_are_up_to_the_app()
    {
        var relaxed = new CaltropPasswordRules { MinLength = 6, MinScore = 0, BlockCommon = false };
        Assert.True(Caltrop.Passwords.Check("dragon", relaxed).Ok);

        var strict = new CaltropPasswordRules { MinLength = 30, MinScore = 4 };
        Assert.False(Caltrop.Passwords.Check("correct horse battery", strict).Ok);

        var maxLength = new CaltropPasswordRules { MaxLength = 16 };
        Assert.Contains("Use at most 16 characters.", Caltrop.Passwords.Check("correct horse battery staple", maxLength).Problems);

        Assert.Throws<ArgumentOutOfRangeException>(() => new CaltropPasswordRules { MinScore = 5 });
        Assert.Throws<ArgumentOutOfRangeException>(() => new CaltropPasswordRules { MinLength = 0 });
    }

    [Fact]
    public void Broken_text_is_checked_without_throwing()
    {
        Assert.False(Caltrop.Passwords.Check("\uD800\uD800abc").Ok);
        Assert.False(Caltrop.Passwords.Check(string.Empty).Ok);
    }

    [Fact]
    public void Strength_names_match_scores()
    {
        Assert.Equal("Very weak", Caltrop.Passwords.Check("password").Strength);
        Assert.Equal("Very strong", Caltrop.Passwords.Check("correct horse battery staple").Strength);
    }
}
