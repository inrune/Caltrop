using System.Buffers.Binary;
using System.Buffers.Text;
using CaltropSecurity.Internal;

namespace CaltropSecurity.Tests;

public class PasswordEncryptionTests
{
    /// <summary>A password message with the minimum iteration count, so tests stay fast.</summary>
    internal static byte[] FastPasswordMessage(string text, string password) =>
        PasswordMessages.Encrypt(Encodings.Utf8(text, "text"), password, PasswordKdf.MinimumIterations);

    [Fact]
    public void Text_round_trips_with_the_default_settings()
    {
        string encrypted = Caltrop.EncryptWithPassword("my diary", "correct horse battery staple");

        Assert.Matches(TestData.Base64UrlPattern, encrypted);
        Assert.Equal("my diary", Caltrop.DecryptWithPassword(encrypted, "correct horse battery staple"));
    }

    [Fact]
    public void Bytes_round_trip()
    {
        byte[] data = TestData.RandomBytes(500);

        byte[] encrypted = Caltrop.EncryptWithPassword(data, "pw");

        Assert.Equal(data, Caltrop.DecryptWithPassword(encrypted, "pw"));
    }

    [Fact]
    public void The_iteration_count_is_stored_in_the_header()
    {
        byte[] encrypted = Caltrop.EncryptWithPassword([1], "pw");

        Assert.Equal(0x02, encrypted[1]);
        Assert.Equal(600_000, BinaryPrimitives.ReadInt32BigEndian(encrypted.AsSpan(2)));
    }

    [Fact]
    public void A_wrong_password_fails()
    {
        string encrypted = Base64Url.EncodeToString(FastPasswordMessage("secret", "right"));

        CaltropException ex = TestData.Throws(CaltropErrorCode.AuthenticationFailed, () => Caltrop.DecryptWithPassword(encrypted, "wrong"));
        Assert.Contains("password", ex.Message);
    }

    [Fact]
    public void Tampering_is_detected()
    {
        byte[] encrypted = FastPasswordMessage("secret", "pw");

        foreach (int i in new[] { 10, 30, encrypted.Length - 1 })
        {
            byte[] tampered = TestData.FlipBit(encrypted, i);
            TestData.Throws(CaltropErrorCode.AuthenticationFailed, () => Caltrop.DecryptWithPassword(tampered, "pw"));
        }
    }

    [Fact]
    public void An_absurd_iteration_count_is_rejected_without_running_it()
    {
        byte[] encrypted = FastPasswordMessage("secret", "pw");
        BinaryPrimitives.WriteInt32BigEndian(encrypted.AsSpan(2), int.MaxValue);

        TestData.Throws(CaltropErrorCode.InvalidFormat, () => Caltrop.DecryptWithPassword(encrypted, "pw"));
    }

    [Fact]
    public void Empty_passwords_are_rejected()
    {
        Assert.Throws<ArgumentException>(() => Caltrop.EncryptWithPassword("x", ""));
        Assert.Throws<ArgumentNullException>(() => Caltrop.EncryptWithPassword("x", null!));
    }

    [Fact]
    public void Key_encrypted_data_gets_a_helpful_error()
    {
        using var key = CaltropKey.Generate();
        string encrypted = Caltrop.Encrypt("x", key);

        CaltropException ex = TestData.Throws(CaltropErrorCode.WrongDataType, () => Caltrop.DecryptWithPassword(encrypted, "pw"));
        Assert.Contains("Caltrop.Decrypt(data, key)", ex.Message);
    }
}
