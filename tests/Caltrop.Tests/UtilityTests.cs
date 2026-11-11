namespace CaltropSecurity.Tests;

public class UtilityTests
{
    [Theory]
    [InlineData("abc", "abc", true)]
    [InlineData("abc", "abd", false)]
    [InlineData("abc", "abcd", false)]
    [InlineData("", "", true)]
    [InlineData(null, null, true)]
    [InlineData(null, "", false)]
    [InlineData("é", "é", false)]
    public void SecureEquals_compares_strings(string? a, string? b, bool expected)
    {
        Assert.Equal(expected, Caltrop.SecureEquals(a, b));
        Assert.Equal(expected, Caltrop.SecureEquals(b, a));
    }

    [Fact]
    public void SecureEquals_compares_bytes()
    {
        Assert.True(Caltrop.SecureEquals(new byte[] { 1, 2 }, new byte[] { 1, 2 }));
        Assert.False(Caltrop.SecureEquals(new byte[] { 1, 2 }, new byte[] { 1, 3 }));
        Assert.False(Caltrop.SecureEquals(new byte[] { 1 }, null));
        Assert.True(Caltrop.SecureEquals((byte[]?)null, null));
    }
}
