using System.Text;

namespace CaltropSecurity.Tests;

public class SignatureTests
{
    // A fresh key for every test, so a lockdown test can never wipe a key another test is using.
    private readonly CaltropKeyPair _signer = CaltropKeyPair.Generate();
    // A fresh key for every test, so a lockdown test can never wipe a key another test is using.
    private readonly CaltropKeyPair _other = CaltropKeyPair.Generate();

    [Fact]
    public void A_signature_verifies_with_the_signers_public_key()
    {
        string signature = Caltrop.Sign("release v1.2.0", _signer);

        Assert.Equal(94, signature.Length);
        Assert.Matches(TestData.Base64UrlPattern, signature);
        Assert.True(Caltrop.VerifySignature("release v1.2.0", signature, _signer.PublicKey));
    }

    [Fact]
    public void A_changed_message_fails()
    {
        string signature = Caltrop.Sign("pay $10", _signer);

        Assert.False(Caltrop.VerifySignature("pay $1000", signature, _signer.PublicKey));
    }

    [Fact]
    public void Another_key_fails()
    {
        string signature = Caltrop.Sign("hello", _signer);

        Assert.False(Caltrop.VerifySignature("hello", signature, _other.PublicKey));
        Assert.False(Caltrop.VerifySignature("hello", Caltrop.Sign("hello", _other), _signer.PublicKey));
    }

    [Fact]
    public void Any_changed_character_fails_without_throwing()
    {
        string signature = Caltrop.Sign("hello", _signer);

        for (int i = 0; i < signature.Length; i++)
        {
            char[] chars = signature.ToCharArray();
            chars[i] = chars[i] == 'A' ? 'B' : 'A';
            Assert.False(Caltrop.VerifySignature("hello", new string(chars), _signer.PublicKey));
        }
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("abc")]
    [InlineData("not a signature at all, not even base64!")]
    public void Malformed_signatures_return_false(string? signature)
    {
        Assert.False(Caltrop.VerifySignature("hello", signature, _signer.PublicKey));
    }

    [Fact]
    public void Text_bytes_and_streams_are_signed_the_same_way()
    {
        byte[] data = Encoding.UTF8.GetBytes("same content");

        string fromText = Caltrop.Sign("same content", _signer);
        string fromBytes = Caltrop.Sign(data, _signer);
        string fromStream = Caltrop.Sign(new MemoryStream(data), _signer);

        foreach (string signature in new[] { fromText, fromBytes, fromStream })
        {
            Assert.True(Caltrop.VerifySignature("same content", signature, _signer.PublicKey));
            Assert.True(Caltrop.VerifySignature(data, signature, _signer.PublicKey));
            Assert.True(Caltrop.VerifySignature(new MemoryStream(data), signature, _signer.PublicKey));
        }
    }

    [Fact]
    public void Large_streams_can_be_signed()
    {
        byte[] data = TestData.RandomBytes(300_000);

        string signature = Caltrop.Sign(new MemoryStream(data), _signer);

        Assert.True(Caltrop.VerifySignature(new MemoryStream(data), signature, _signer.PublicKey));
        data[^1] ^= 1;
        Assert.False(Caltrop.VerifySignature(new MemoryStream(data), signature, _signer.PublicKey));
    }
}
