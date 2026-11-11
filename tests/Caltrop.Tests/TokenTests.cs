using System.Buffers.Text;

namespace CaltropSecurity.Tests;

public class TokenTests
{
    private static readonly CaltropKey s_key = CaltropKey.Generate();
    private static readonly DateTimeOffset s_now = new(2026, 11, 10, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void A_token_carries_its_payload()
    {
        string token = Caltrop.Tokens.Create("user-42", s_key, TimeSpan.FromHours(1));

        Assert.Matches(TestData.Base64UrlPattern, token);
        Assert.Equal("user-42", Caltrop.Tokens.Validate(token, s_key));
        Assert.True(Caltrop.Tokens.TryValidate(token, s_key, out string? payload));
        Assert.Equal("user-42", payload);
    }

    [Fact]
    public void The_payload_is_not_readable_from_the_token()
    {
        string token = Caltrop.Tokens.Create("visible?", s_key, TimeSpan.FromHours(1));
        byte[] raw = Base64Url.DecodeFromChars(token);

        Assert.DoesNotContain("visible?", System.Text.Encoding.UTF8.GetString(raw));
    }

    [Fact]
    public void A_token_expires_after_its_lifetime()
    {
        string token = Caltrop.Tokens.Create("x", s_key, TimeSpan.FromHours(1), null, s_now);
        CaltropKey[] keys = [s_key];

        Assert.Equal("x", Caltrop.Tokens.Validate(token, keys, null, s_now.AddMinutes(59)));
        TestData.Throws(CaltropErrorCode.TokenExpired, () => Caltrop.Tokens.Validate(token, keys, null, s_now.AddHours(1)));
        TestData.Throws(CaltropErrorCode.TokenExpired, () => Caltrop.Tokens.Validate(token, keys, null, s_now.AddDays(3)));
        Assert.False(Caltrop.Tokens.TryValidate(token, keys, null, s_now.AddHours(2), out _));
    }

    [Fact]
    public void A_never_expiring_token_can_be_made_with_TimeSpan_MaxValue()
    {
        string token = Caltrop.Tokens.Create("forever", s_key, TimeSpan.MaxValue, null, s_now);

        Assert.Equal("forever", Caltrop.Tokens.Validate(token, [s_key], null, new DateTimeOffset(9000, 1, 1, 0, 0, 0, TimeSpan.Zero)));
    }

    [Fact]
    public void The_purpose_must_match()
    {
        string token = Caltrop.Tokens.Create("user-42", s_key, TimeSpan.FromHours(1), purpose: "password-reset");

        Assert.Equal("user-42", Caltrop.Tokens.Validate(token, s_key, purpose: "password-reset"));
        TestData.Throws(CaltropErrorCode.AuthenticationFailed, () => Caltrop.Tokens.Validate(token, s_key, purpose: "email-verify"));
        TestData.Throws(CaltropErrorCode.AuthenticationFailed, () => Caltrop.Tokens.Validate(token, s_key));
    }

    [Fact]
    public void Tampered_tokens_are_rejected()
    {
        byte[] raw = Base64Url.DecodeFromChars(Caltrop.Tokens.Create("user-42", s_key, TimeSpan.FromHours(1)));

        for (int i = 0; i < raw.Length; i++)
        {
            string tampered = Base64Url.EncodeToString(TestData.FlipBit(raw, i, bit: i % 8));
            Assert.Throws<CaltropException>(() => Caltrop.Tokens.Validate(tampered, s_key));
            Assert.False(Caltrop.Tokens.TryValidate(tampered, s_key, out _));
        }
    }

    [Fact]
    public void A_tampered_expired_token_is_reported_as_invalid_not_expired()
    {
        byte[] raw = Base64Url.DecodeFromChars(Caltrop.Tokens.Create("x", s_key, TimeSpan.FromMinutes(5), null, s_now));
        raw[^1] ^= 1;

        TestData.Throws(CaltropErrorCode.AuthenticationFailed, () => Caltrop.Tokens.Validate(Base64Url.EncodeToString(raw), [s_key], null, s_now.AddDays(1)));
    }

    [Fact]
    public void Moving_the_expiry_forward_is_detected()
    {
        byte[] raw = Base64Url.DecodeFromChars(Caltrop.Tokens.Create("x", s_key, TimeSpan.FromMinutes(5), null, s_now));
        raw[45] ^= 0x10; // inside the expiry timestamp

        TestData.Throws(CaltropErrorCode.AuthenticationFailed, () => Caltrop.Tokens.Validate(Base64Url.EncodeToString(raw), [s_key], null, s_now));
    }

    [Fact]
    public void Tokens_from_another_key_are_rejected()
    {
        using var other = CaltropKey.Generate();
        string token = Caltrop.Tokens.Create("x", other, TimeSpan.FromHours(1));

        TestData.Throws(CaltropErrorCode.KeyMismatch, () => Caltrop.Tokens.Validate(token, s_key));
    }

    [Fact]
    public void A_key_ring_accepts_tokens_from_older_keys()
    {
        using var oldKey = CaltropKey.Generate();
        string token = Caltrop.Tokens.Create("x", oldKey, TimeSpan.FromHours(1));
        var ring = new CaltropKeyRing(s_key, oldKey);

        Assert.Equal("x", Caltrop.Tokens.Validate(token, ring));
        Assert.True(Caltrop.Tokens.TryValidate(token, ring, out string? payload));
        Assert.Equal("x", payload);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("garbage")]
    [InlineData("AQQ")]
    public void TryValidate_returns_false_for_junk(string? token)
    {
        Assert.False(Caltrop.Tokens.TryValidate(token, s_key, out string? payload));
        Assert.Null(payload);
    }

    [Fact]
    public void Encrypted_messages_are_not_tokens()
    {
        string message = Caltrop.Encrypt("x", s_key);

        TestData.Throws(CaltropErrorCode.WrongDataType, () => Caltrop.Tokens.Validate(message, s_key));
    }

    [Fact]
    public void Lifetime_must_be_positive()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => Caltrop.Tokens.Create("x", s_key, TimeSpan.Zero));
        Assert.Throws<ArgumentOutOfRangeException>(() => Caltrop.Tokens.Create("x", s_key, TimeSpan.FromSeconds(-1)));
    }
}
