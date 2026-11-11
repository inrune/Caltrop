using System.Buffers.Text;
using CaltropSecurity.Internal;

namespace CaltropSecurity.Tests;

public class PublicKeyTests
{
    private static readonly CaltropKeyPair s_alice = CaltropKeyPair.Generate();
    private static readonly CaltropKeyPair s_bob = CaltropKeyPair.Generate();

    [Theory]
    [InlineData("meet at noon")]
    [InlineData("")]
    [InlineData("ünïcödé ✓")]
    public void Only_the_recipient_can_decrypt(string text)
    {
        string encrypted = Caltrop.Encrypt(text, s_alice.PublicKey);

        Assert.Equal(text, Caltrop.Decrypt(encrypted, s_alice));
        TestData.Throws(CaltropErrorCode.KeyMismatch, () => Caltrop.Decrypt(encrypted, s_bob));
    }

    [Fact]
    public void Bytes_round_trip_with_87_bytes_of_overhead()
    {
        byte[] data = TestData.RandomBytes(100);

        byte[] encrypted = Caltrop.Encrypt(data, s_alice.PublicKey);

        Assert.Equal(100 + 87, encrypted.Length);
        Assert.Equal(0x03, encrypted[1]);
        Assert.Equal(data, Caltrop.Decrypt(encrypted, s_alice));
    }

    [Fact]
    public void Every_message_uses_a_new_ephemeral_key()
    {
        byte[] a = Caltrop.Encrypt([1, 2, 3], s_alice.PublicKey);
        byte[] b = Caltrop.Encrypt([1, 2, 3], s_alice.PublicKey);

        Assert.NotEqual(a.AsSpan(6, 65).ToArray(), b.AsSpan(6, 65).ToArray());
    }

    [Fact]
    public void Changing_any_bit_is_detected()
    {
        byte[] encrypted = Caltrop.Encrypt(TestData.RandomBytes(8), s_alice.PublicKey);

        for (int i = 0; i < encrypted.Length; i++)
        {
            byte[] tampered = TestData.FlipBit(encrypted, i, bit: (i * 3) % 8);
            Assert.Throws<CaltropException>(() => Caltrop.Decrypt(tampered, s_alice));
        }
    }

    [Fact]
    public void An_ephemeral_key_that_is_not_on_the_curve_is_rejected()
    {
        byte[] encrypted = Caltrop.Encrypt([1, 2, 3], s_alice.PublicKey);
        encrypted.AsSpan(7, 64).Fill(0x01); // X and Y of the ephemeral point

        TestData.Throws(CaltropErrorCode.InvalidFormat, () => Caltrop.Decrypt(encrypted, s_alice));
    }

    [Fact]
    public void Context_must_match()
    {
        string encrypted = Caltrop.Encrypt("x", s_alice.PublicKey, context: "invoice-42");

        Assert.Equal("x", Caltrop.Decrypt(encrypted, s_alice, context: "invoice-42"));
        TestData.Throws(CaltropErrorCode.AuthenticationFailed, () => Caltrop.Decrypt(encrypted, s_alice, context: "invoice-43"));
    }

    [Fact]
    public void Public_keys_export_and_parse()
    {
        string text = s_alice.PublicKey.Export();

        CaltropPublicKey parsed = CaltropPublicKey.Parse(text);

        Assert.StartsWith("ctpub_", text);
        Assert.Equal(s_alice.PublicKey, parsed);
        Assert.Equal(s_alice.PublicKey.GetHashCode(), parsed.GetHashCode());
        Assert.Equal(s_alice.Id, parsed.Id);
        Assert.NotEqual(s_bob.PublicKey, parsed);
        Assert.Equal("x", Caltrop.Decrypt(Caltrop.Encrypt("x", parsed), s_alice));
    }

    [Fact]
    public void Private_keys_export_and_parse()
    {
        string text = s_alice.ExportPrivateKey();

        using var parsed = CaltropKeyPair.Parse(text);

        Assert.StartsWith("ctprv_", text);
        Assert.Equal(s_alice.PublicKey, parsed.PublicKey);
        Assert.Equal("x", Caltrop.Decrypt(Caltrop.Encrypt("x", s_alice.PublicKey), parsed));
        Assert.True(Caltrop.VerifySignature("m", Caltrop.Sign("m", parsed), s_alice.PublicKey));
    }

    [Fact]
    public void Mixing_up_public_and_private_keys_gives_helpful_errors()
    {
        CaltropException publicAsPrivate = TestData.Throws(CaltropErrorCode.InvalidKey, () => CaltropKeyPair.Parse(s_alice.PublicKey.Export()));
        CaltropException privateAsPublic = TestData.Throws(CaltropErrorCode.InvalidKey, () => CaltropPublicKey.Parse(s_alice.ExportPrivateKey()));

        Assert.Contains("public key", publicAsPrivate.Message);
        Assert.Contains("private key", privateAsPublic.Message);
    }

    [Fact]
    public void A_private_key_whose_halves_do_not_match_is_rejected()
    {
        Assert.True(KeyText.TryDecode(s_alice.ExportPrivateKey(), CaltropKeyPair.Prefix, 192, out byte[] alice, out _));
        Assert.True(KeyText.TryDecode(s_bob.ExportPrivateKey(), CaltropKeyPair.Prefix, 192, out byte[] bob, out _));
        byte[] mixed = [.. alice[..128], .. bob[128..]];

        CaltropException ex = TestData.Throws(CaltropErrorCode.InvalidKey, () => CaltropKeyPair.Parse(KeyText.Encode(CaltropKeyPair.Prefix, mixed)));
        Assert.Contains("do not match", ex.Message);
    }

    [Fact]
    public void A_public_key_with_a_point_off_the_curve_is_rejected()
    {
        byte[] bogus = new byte[128];
        bogus.AsSpan().Fill(0x01);

        TestData.Throws(CaltropErrorCode.InvalidKey, () => CaltropPublicKey.Parse(KeyText.Encode(CaltropPublicKey.Prefix, bogus)));
    }

    [Fact]
    public void Damaged_key_text_is_rejected()
    {
        string text = s_alice.PublicKey.Export();

        Assert.False(CaltropPublicKey.TryParse(text[..^2], out _));
        Assert.False(CaltropPublicKey.TryParse(null, out _));
        Assert.False(CaltropKeyPair.TryParse("ctprv_nope", out _));
    }

    [Fact]
    public void Key_pair_ToString_never_contains_the_private_key()
    {
        Assert.Equal($"CaltropKeyPair({s_alice.Id})", s_alice.ToString());
    }

    [Fact]
    public void A_disposed_key_pair_cannot_be_used()
    {
        var keyPair = CaltropKeyPair.Generate();
        string encrypted = Caltrop.Encrypt("x", keyPair.PublicKey);
        keyPair.Dispose();

        Assert.Throws<ObjectDisposedException>(() => Caltrop.Decrypt(encrypted, keyPair));
        Assert.Throws<ObjectDisposedException>(() => Caltrop.Sign("x", keyPair));
        Assert.Throws<ObjectDisposedException>(() => keyPair.ExportPrivateKey());
    }

    [Fact]
    public void Secret_key_data_gets_a_helpful_error()
    {
        using var key = CaltropKey.Generate();
        string encrypted = Caltrop.Encrypt("x", key);

        TestData.Throws(CaltropErrorCode.WrongDataType, () => Caltrop.Decrypt(encrypted, s_alice));
        Assert.Matches(TestData.Base64UrlPattern, Base64Url.EncodeToString(Caltrop.Encrypt([1], s_alice.PublicKey)));
    }
}
