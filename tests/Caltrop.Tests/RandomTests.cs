namespace CaltropSecurity.Tests;

public class RandomTests
{
    [Fact]
    public void Bytes_returns_the_requested_amount()
    {
        Assert.Equal(32, Caltrop.Random.Bytes(32).Length);
        Assert.Empty(Caltrop.Random.Bytes(0));
        Assert.NotEqual(Caltrop.Random.Bytes(16), Caltrop.Random.Bytes(16));
        Assert.Throws<ArgumentOutOfRangeException>(() => Caltrop.Random.Bytes(-1));
    }

    [Fact]
    public void Numbers_stay_in_range()
    {
        for (int i = 0; i < 1000; i++)
        {
            Assert.InRange(Caltrop.Random.Number(10), 0, 9);
            Assert.InRange(Caltrop.Random.Number(-5, 5), -5, 4);
        }
    }

    [Fact]
    public void Numbers_cover_the_whole_range()
    {
        var seen = new HashSet<int>();
        for (int i = 0; i < 2000; i++)
        {
            seen.Add(Caltrop.Random.Number(1, 7));
        }

        Assert.Equal(6, seen.Count);
    }

    [Fact]
    public void Strings_use_letters_and_digits_by_default()
    {
        Assert.Matches("^[A-Za-z0-9]{24}$", Caltrop.Random.String(24));
        Assert.Equal(string.Empty, Caltrop.Random.String(0));
    }

    [Fact]
    public void Strings_can_use_a_custom_alphabet()
    {
        Assert.Matches("^[01]{64}$", Caltrop.Random.String(64, "01"));
        Assert.Matches("^[0-9]{6}$", Caltrop.Random.String(6, "0123456789"));
    }

    [Theory]
    [InlineData("")]
    [InlineData("a")]
    [InlineData("aab")]
    public void Bad_alphabets_are_rejected(string alphabet)
    {
        Assert.Throws<ArgumentException>(() => Caltrop.Random.String(10, alphabet));
    }

    [Fact]
    public void Tokens_are_url_safe_and_256_bits_by_default()
    {
        string token = Caltrop.Random.Token();

        Assert.Equal(43, token.Length);
        Assert.Matches(TestData.Base64UrlPattern, token);
        Assert.NotEqual(token, Caltrop.Random.Token());
        Assert.Equal(22, Caltrop.Random.Token(16).Length);
        Assert.Throws<ArgumentOutOfRangeException>(() => Caltrop.Random.Token(15));
    }

    [Fact]
    public void Passwords_contain_every_kind_of_character_and_nothing_confusing()
    {
        for (int i = 0; i < 200; i++)
        {
            string password = Caltrop.Random.Password(8);

            Assert.Equal(8, password.Length);
            Assert.Matches("[A-Z]", password);
            Assert.Matches("[a-z]", password);
            Assert.Matches("[0-9]", password);
            Assert.Matches("[^A-Za-z0-9]", password);
            Assert.DoesNotMatch("[Il1O0]", password);
        }

        Assert.Equal(20, Caltrop.Random.Password().Length);
    }

    [Theory]
    [InlineData(7)]
    [InlineData(1025)]
    public void Password_length_is_limited(int length)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => Caltrop.Random.Password(length));
    }
}
