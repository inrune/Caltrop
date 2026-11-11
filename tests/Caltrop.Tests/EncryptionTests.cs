using System.Buffers.Text;
using System.Security.Cryptography;

namespace CaltropSecurity.Tests;

public class EncryptionTests
{
    private static readonly CaltropKey s_key = CaltropKey.Generate();

    [Theory]
    [InlineData("hello")]
    [InlineData("")]
    [InlineData("héllo wörld 👋 世界")]
    [InlineData("line one\nline two\0with a null")]
    public void Text_round_trips(string text)
    {
        string encrypted = Caltrop.Encrypt(text, s_key);

        Assert.Equal(text, Caltrop.Decrypt(encrypted, s_key));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(1000)]
    [InlineData(1_000_000)]
    public void Bytes_round_trip(int length)
    {
        byte[] data = TestData.RandomBytes(length);

        byte[] encrypted = Caltrop.Encrypt(data, s_key);

        Assert.Equal(data, Caltrop.Decrypt(encrypted, s_key));
    }

    [Fact]
    public void Encrypted_text_is_url_safe()
    {
        Assert.Matches(TestData.Base64UrlPattern, Caltrop.Encrypt("some text?&/=", s_key));
    }

    [Fact]
    public void Encrypting_the_same_text_twice_gives_different_results()
    {
        Assert.NotEqual(Caltrop.Encrypt("same", s_key), Caltrop.Encrypt("same", s_key));
    }

    [Fact]
    public void Output_is_the_input_plus_46_bytes_with_a_versioned_header()
    {
        byte[] encrypted = Caltrop.Encrypt(new byte[10], s_key);

        Assert.Equal(10 + 46, encrypted.Length);
        Assert.Equal(0x01, encrypted[0]); // format version
        Assert.Equal(0x01, encrypted[1]); // secret-key message
    }

    [Fact]
    public void Plaintext_does_not_appear_in_the_output()
    {
        byte[] plaintext = new byte[64];
        byte[] encrypted = Caltrop.Encrypt(plaintext, s_key);

        Assert.False(encrypted.AsSpan(30, 64).SequenceEqual(plaintext));
    }

    [Fact]
    public void A_different_key_is_reported_as_a_key_mismatch()
    {
        string encrypted = Caltrop.Encrypt("secret", s_key);
        using var other = CaltropKey.Generate();

        CaltropException ex = TestData.Throws(CaltropErrorCode.KeyMismatch, () => Caltrop.Decrypt(encrypted, other));
        Assert.Contains(s_key.Id, ex.Message);
    }

    [Fact]
    public void Changing_any_bit_is_detected()
    {
        byte[] encrypted = Caltrop.Encrypt(TestData.RandomBytes(10), s_key);

        for (int i = 0; i < encrypted.Length; i++)
        {
            byte[] tampered = TestData.FlipBit(encrypted, i, bit: i % 8);
            CaltropException ex = Assert.Throws<CaltropException>(() => Caltrop.Decrypt(tampered, s_key));
            if (i >= 6)
            {
                Assert.Equal(CaltropErrorCode.AuthenticationFailed, ex.ErrorCode);
            }
        }
    }

    [Fact]
    public void Cutting_off_any_amount_is_detected()
    {
        byte[] encrypted = Caltrop.Encrypt(TestData.RandomBytes(10), s_key);

        for (int length = 0; length < encrypted.Length; length++)
        {
            byte[] truncated = encrypted[..length];
            Assert.Throws<CaltropException>(() => Caltrop.Decrypt(truncated, s_key));
        }
    }

    [Fact]
    public void Context_must_match()
    {
        string encrypted = Caltrop.Encrypt("555-12-3456", s_key, context: "user:1");

        Assert.Equal("555-12-3456", Caltrop.Decrypt(encrypted, s_key, context: "user:1"));
        TestData.Throws(CaltropErrorCode.AuthenticationFailed, () => Caltrop.Decrypt(encrypted, s_key, context: "user:2"));
        TestData.Throws(CaltropErrorCode.AuthenticationFailed, () => Caltrop.Decrypt(encrypted, s_key));
    }

    [Fact]
    public void Byte_context_must_match()
    {
        byte[] data = TestData.RandomBytes(20);
        byte[] encrypted = Caltrop.Encrypt(data, s_key, [1, 2, 3]);

        Assert.Equal(data, Caltrop.Decrypt(encrypted, s_key, [1, 2, 3]));
        TestData.Throws(CaltropErrorCode.AuthenticationFailed, () => Caltrop.Decrypt(encrypted, s_key, [1, 2, 4]));
    }

    [Fact]
    public void A_key_ring_decrypts_data_from_any_of_its_keys()
    {
        using var oldKey = CaltropKey.Generate();
        using var newKey = CaltropKey.Generate();
        string oldData = Caltrop.Encrypt("from last year", oldKey);
        var ring = new CaltropKeyRing(newKey, oldKey);

        Assert.Equal("from last year", Caltrop.Decrypt(oldData, ring));
        Assert.Equal("new", Caltrop.Decrypt(Caltrop.Encrypt("new", ring.Primary), ring));
        TestData.Throws(CaltropErrorCode.KeyMismatch, () => Caltrop.Decrypt(oldData, new CaltropKeyRing(newKey)));
    }

    [Fact]
    public void An_empty_key_collection_is_rejected()
    {
        string encrypted = Caltrop.Encrypt("x", s_key);

        Assert.Throws<ArgumentException>(() => Caltrop.Decrypt(encrypted, Array.Empty<CaltropKey>()));
    }

    [Fact]
    public void Password_encrypted_data_gets_a_helpful_error()
    {
        byte[] passwordData = PasswordEncryptionTests.FastPasswordMessage("x", "pw");

        CaltropException ex = TestData.Throws(CaltropErrorCode.WrongDataType, () => Caltrop.Decrypt(Base64Url.EncodeToString(passwordData), s_key));
        Assert.Contains("DecryptWithPassword", ex.Message);
    }

    [Theory]
    [InlineData("not encrypted at all")]
    [InlineData("aGVsbG8gd29ybGQ")]
    [InlineData("AQ")]
    public void Non_caltrop_text_is_rejected(string text)
    {
        CaltropException ex = Assert.Throws<CaltropException>(() => Caltrop.Decrypt(text, s_key));
        Assert.Equal(CaltropErrorCode.InvalidFormat, ex.ErrorCode);
    }

    [Fact]
    public void Data_from_a_newer_format_version_is_reported_as_such()
    {
        byte[] encrypted = Caltrop.Encrypt([1, 2, 3], s_key);
        encrypted[0] = 0x02;

        TestData.Throws(CaltropErrorCode.UnsupportedVersion, () => Caltrop.Decrypt(encrypted, s_key));
    }

    [Fact]
    public void Text_with_invalid_unicode_is_rejected_instead_of_changed()
    {
        Assert.Throws<ArgumentException>(() => Caltrop.Encrypt("bad \uD800 surrogate", s_key));
    }

    [Fact]
    public void Decrypting_non_text_bytes_as_text_gives_a_clear_error()
    {
        string encrypted = Base64Url.EncodeToString(Caltrop.Encrypt([0xFF, 0xFE], s_key));

        CaltropException ex = TestData.Throws(CaltropErrorCode.InvalidFormat, () => Caltrop.Decrypt(encrypted, s_key));
        Assert.Contains("byte[]", ex.Message);
    }

    [Fact]
    public void Exceptions_can_be_caught_as_CryptographicException()
    {
        using var other = CaltropKey.Generate();
        string encrypted = Caltrop.Encrypt("x", s_key);

        Assert.ThrowsAny<CryptographicException>(() => Caltrop.Decrypt(encrypted, other));
    }

    [Fact]
    public void Null_arguments_are_rejected()
    {
        Assert.Throws<ArgumentNullException>(() => Caltrop.Encrypt((string)null!, s_key));
        Assert.Throws<ArgumentNullException>(() => Caltrop.Encrypt("x", (CaltropKey)null!));
        Assert.Throws<ArgumentNullException>(() => Caltrop.Decrypt((string)null!, s_key));
        Assert.Throws<ArgumentNullException>(() => Caltrop.Decrypt("x", (CaltropKey)null!));
        Assert.Throws<ArgumentNullException>(() => Caltrop.Encrypt((byte[])null!, s_key));
    }
}
