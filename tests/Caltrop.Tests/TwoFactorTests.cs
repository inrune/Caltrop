using System.Text;

namespace CaltropSecurity.Tests;

public class TwoFactorTests
{
    // The secret from RFC 4226 and RFC 6238: ASCII "12345678901234567890".
    private const string RfcSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    private static readonly byte[] s_rfcKey = Encoding.ASCII.GetBytes("12345678901234567890");

    [Theory]
    [InlineData(0L, 755224)]
    [InlineData(1L, 287082)]
    [InlineData(2L, 359152)]
    [InlineData(3L, 969429)]
    [InlineData(4L, 338314)]
    [InlineData(5L, 254676)]
    [InlineData(6L, 287922)]
    [InlineData(7L, 162583)]
    [InlineData(8L, 399871)]
    [InlineData(9L, 520489)]
    public void Matches_the_RFC_4226_test_vectors(long counter, int expected)
    {
        Assert.Equal(expected, Caltrop.TwoFactor.Hotp(s_rfcKey, counter, 6));
    }

    [Theory]
    [InlineData(59L, "94287082")]
    [InlineData(1111111109L, "07081804")]
    [InlineData(1111111111L, "14050471")]
    [InlineData(1234567890L, "89005924")]
    [InlineData(2000000000L, "69279037")]
    [InlineData(20000000000L, "65353130")]
    public void Matches_the_RFC_6238_test_vectors(long unixTime, string expected)
    {
        long step = unixTime / 30;

        Assert.Equal(expected, Caltrop.TwoFactor.FormatCode(Caltrop.TwoFactor.Hotp(s_rfcKey, step, 8), 8));
        Assert.Equal(expected[2..], Caltrop.TwoFactor.GetCode(RfcSecret, DateTimeOffset.FromUnixTimeSeconds(unixTime)));
    }

    [Fact]
    public void The_current_code_verifies()
    {
        string secret = Caltrop.TwoFactor.CreateSecret();

        Assert.True(Caltrop.TwoFactor.Verify(secret, Caltrop.TwoFactor.GetCode(secret)));
    }

    [Fact]
    public void Codes_from_one_step_either_side_are_accepted_but_not_further()
    {
        DateTimeOffset now = DateTimeOffset.FromUnixTimeSeconds(1_800_000_015);
        string Code(int seconds) => Caltrop.TwoFactor.GetCode(RfcSecret, now.AddSeconds(seconds));

        Assert.True(Caltrop.TwoFactor.Verify(RfcSecret, Code(0), now, long.MinValue, out _));
        Assert.True(Caltrop.TwoFactor.Verify(RfcSecret, Code(-30), now, long.MinValue, out _));
        Assert.True(Caltrop.TwoFactor.Verify(RfcSecret, Code(30), now, long.MinValue, out _));
        Assert.False(Caltrop.TwoFactor.Verify(RfcSecret, Code(-60), now, long.MinValue, out _));
        Assert.False(Caltrop.TwoFactor.Verify(RfcSecret, Code(60), now, long.MinValue, out _));
    }

    [Fact]
    public void A_code_cannot_be_used_twice_with_replay_protection()
    {
        DateTimeOffset now = DateTimeOffset.FromUnixTimeSeconds(1_800_000_015);
        string code = Caltrop.TwoFactor.GetCode(RfcSecret, now);

        Assert.True(Caltrop.TwoFactor.Verify(RfcSecret, code, now, 0, out long usedStep));
        Assert.Equal(1_800_000_015L / 30, usedStep);
        Assert.False(Caltrop.TwoFactor.Verify(RfcSecret, code, now, usedStep, out _));
        Assert.True(Caltrop.TwoFactor.Verify(RfcSecret, Caltrop.TwoFactor.GetCode(RfcSecret, now.AddSeconds(30)), now.AddSeconds(30), usedStep, out long next));
        Assert.Equal(usedStep + 1, next);
    }

    [Fact]
    public void Spaces_and_dashes_in_codes_are_ignored()
    {
        DateTimeOffset now = DateTimeOffset.FromUnixTimeSeconds(59);

        Assert.True(Caltrop.TwoFactor.Verify(RfcSecret, "287 082", now, long.MinValue, out _));
        Assert.True(Caltrop.TwoFactor.Verify(RfcSecret, "287-082", now, long.MinValue, out _));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("28708")]
    [InlineData("2870822")]
    [InlineData("abcdef")]
    [InlineData("28708a")]
    [InlineData("２８７０８２")]
    public void Badly_formed_codes_are_rejected(string? code)
    {
        Assert.False(Caltrop.TwoFactor.Verify(RfcSecret, code, DateTimeOffset.FromUnixTimeSeconds(59), long.MinValue, out _));
    }

    [Theory]
    [InlineData("")]
    [InlineData("not base32!")]
    [InlineData("GEZDGNBV")]
    public void Invalid_secrets_are_rejected(string secret)
    {
        Assert.Throws<ArgumentException>(() => Caltrop.TwoFactor.Verify(secret, "123456"));
    }

    [Fact]
    public void New_secrets_are_160_bit_base32()
    {
        string secret = Caltrop.TwoFactor.CreateSecret();

        Assert.Matches("^[A-Z2-7]{32}$", secret);
        Assert.NotEqual(secret, Caltrop.TwoFactor.CreateSecret());
    }

    [Fact]
    public void Lower_case_secrets_with_spaces_work()
    {
        string spaced = "gezd gnbv gy3t qojq gezd gnbv gy3t qojq";

        Assert.Equal(Caltrop.TwoFactor.GetCode(RfcSecret, DateTimeOffset.FromUnixTimeSeconds(59)), Caltrop.TwoFactor.GetCode(spaced, DateTimeOffset.FromUnixTimeSeconds(59)));
    }

    [Fact]
    public void Setup_uri_follows_the_key_uri_format()
    {
        string uri = Caltrop.TwoFactor.GetSetupUri("gezd gnbv gy3t qojq gezd gnbv gy3t qojq", "alice@example.com", "My App");

        Assert.Equal(
            "otpauth://totp/My%20App:alice%40example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=My%20App&algorithm=SHA1&digits=6&period=30",
            uri);
    }

    [Fact]
    public void Setup_uri_rejects_colons_and_empty_names()
    {
        Assert.Throws<ArgumentException>(() => Caltrop.TwoFactor.GetSetupUri(RfcSecret, "alice", "Bad:Issuer"));
        Assert.ThrowsAny<ArgumentException>(() => Caltrop.TwoFactor.GetSetupUri(RfcSecret, " ", "My App"));
    }

    [Fact]
    public void Recovery_codes_are_unique_and_readable()
    {
        string[] codes = Caltrop.TwoFactor.CreateRecoveryCodes();

        Assert.Equal(10, codes.Length);
        Assert.Distinct(codes);
        Assert.All(codes, code => Assert.Matches("^[2-9A-HJKMNP-Z]{4}(-[2-9A-HJKMNP-Z]{4}){3}$", code));
    }

    [Fact]
    public void Recovery_code_hashes_ignore_case_spaces_and_dashes()
    {
        string code = Caltrop.TwoFactor.CreateRecoveryCodes(1)[0];
        string stored = Caltrop.TwoFactor.HashRecoveryCode(code);

        Assert.Matches("^[0-9a-f]{64}$", stored);
        Assert.Equal(stored, Caltrop.TwoFactor.HashRecoveryCode(code.ToLowerInvariant().Replace("-", " ", StringComparison.Ordinal)));
        Assert.NotEqual(stored, Caltrop.TwoFactor.HashRecoveryCode(Caltrop.TwoFactor.CreateRecoveryCodes(1)[0]));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(101)]
    public void Recovery_code_count_is_limited(int count)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => Caltrop.TwoFactor.CreateRecoveryCodes(count));
    }
}
