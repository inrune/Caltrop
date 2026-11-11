using System.Buffers.Text;
using System.Text;

namespace CaltropSecurity.Tests;

/// <summary>
/// Data made by Caltrop 0.1.0. Every later version must still read it exactly like this.
/// If one of these tests fails, a change broke data that users have already stored: fix the code
/// (or introduce a new format version), never these values.
/// </summary>
public class CompatibilityTests
{
    private const string Text = "Caltrop format v1";
    private const string Password = "correct horse battery staple";

    // The key with bytes 0x00..0x1F.
    private const string KeyText = "ctk_AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh9MLcNb";
    private const string KeyId = "f794570e";

    // A key pair made only for these tests. Never use it for anything real.
    private const string PrivateKey = "ctprv_k6I3VOw2Q4D9Xp6btLv_m4BGFY7mb0dL8YdCoRa4MqdHc7trn6LwQ_D5HXl8vydo_Dx2IJqZCH5LtaYMtRdOp7HsTMNRjIhbmTd9qovFA1LUr2DeSz1_6AVYXn3NtTuQR4kxHEugc7iOtcWOv17rjuszuGZ4n7P024pOgral60JSEMn6KzMvc3OLgG2c4ashd07CshbALHWX4rQnd7LPCxW09GLyTtTOO1LCPQUQnQyhBJU7oUBOZdG3QhtRNUQJJFR9Hw";
    private const string PublicKey = "ctpub_k6I3VOw2Q4D9Xp6btLv_m4BGFY7mb0dL8YdCoRa4MqdHc7trn6LwQ_D5HXl8vydo_Dx2IJqZCH5LtaYMtRdOp7HsTMNRjIhbmTd9qovFA1LUr2DeSz1_6AVYXn3NtTuQR4kxHEugc7iOtcWOv17rjuszuGZ4n7P024pOgral60JzFUlg";
    private const string PairId = "3752aa50";

    private const string Message = "AQH3lFcOkl5Plkit7G85j_7jZAm1x1EaJ0RtExvnZOC0meHMuNSy0hLo1Xq8c-YDX2t1zNP5LDHEQmhWGZxG";
    private const string PasswordMessage = "AQIACSfAy6c_p_qO5bz7C0N7WawwZoEFmATYPn5U0jPeGWSHsxF3PIVab7KNYDmqnykgROvCrHNiPuLithu-7Us-VA";
    private const string PublicKeyMessage = "AQM3UqpQBIat8mgF-QxtN6kHRLoyr5QpXitV0Z1OgsI-YdaNSgXvpgyvl6LRQ6-iIx_A3UYqjpZvWqDUZV_7qWYGseANu8LGnpQHRM5T5hseKaFnE-cEZzxV7CKU-2HaJBUBB3mV3MY";
    private const string Signature = "AQc3UqpQgqfmG8a1c1IigUH2fpbFlgwHqA-gfAQ1RLghIKWBPwSKIIHLSAo1AX6tpCyv13c9qjoPoG-Vw4lmBUNcazxZNA";
    private const string Token = "AQT3lFcO3TdD5PLuuq-76YhB2tVyfS9TJ8QIXK5JAAAAAGrzoZYAAAA6__RBf-cujJN9dw1tnCZovpEcAVfnA0phXjPg";
    private const string Stream = "AQX3lFcOUBD_a9aSSEORI5VGiG-CwOZPoUSX_BA1hWST3BgP68G1X2nGyasLrCKoSZZW_3ULCL1GDiO6DPTk";
    private const string PasswordHash = "$pbkdf2-sha256$i=600000$Z2TcZWAEeGlXyeiAq7sFFw$mALEKsGVXr89pEd7F0woGT+CmpABFLpYeWci5hRb6wQ";
    private const string BlindIndex = "05806f8ffb35c8eafdd099c2828086235633ed6a476f3bffe84b879e490ddf12";
    private const string ApiKey = "acme_live_5vE9fo2VVI4yMZlmObtu5SUTBaFhacI11FV9dm";

    [Fact]
    public void Key_text_and_id_are_stable()
    {
        using CaltropKey key = TestKey();
        using var parsed = CaltropKey.Parse(KeyText);

        Assert.Equal(KeyText, key.Export());
        Assert.Equal(KeyId, key.Id);
        Assert.Equal(key.ToBytes(), parsed.ToBytes());
    }

    [Fact]
    public void Key_pair_text_and_id_are_stable()
    {
        using var pair = CaltropKeyPair.Parse(PrivateKey);

        Assert.Equal(PrivateKey, pair.ExportPrivateKey());
        Assert.Equal(PublicKey, pair.PublicKey.Export());
        Assert.Equal(PairId, pair.Id);
    }

    [Fact]
    public void Secret_key_messages_decrypt()
    {
        using CaltropKey key = TestKey();

        Assert.Equal(Text, Caltrop.Decrypt(Message, key, context: "compat"));
    }

    [Fact]
    public void Password_messages_decrypt()
    {
        Assert.Equal(Text, Caltrop.DecryptWithPassword(PasswordMessage, Password));
    }

    [Fact]
    public void Public_key_messages_decrypt()
    {
        using var pair = CaltropKeyPair.Parse(PrivateKey);

        Assert.Equal(Text, Caltrop.Decrypt(PublicKeyMessage, pair, context: "compat"));
    }

    [Fact]
    public void Signatures_verify()
    {
        Assert.True(Caltrop.VerifySignature(Text, Signature, CaltropPublicKey.Parse(PublicKey)));
    }

    [Fact]
    public void Tokens_validate()
    {
        using CaltropKey key = TestKey();

        Assert.Equal("user-42", Caltrop.Tokens.Validate(Token, key, purpose: "compat"));
    }

    [Fact]
    public void Streams_decrypt()
    {
        using CaltropKey key = TestKey();
        var output = new MemoryStream();

        Caltrop.Files.Decrypt(new MemoryStream(Base64Url.DecodeFromChars(Stream)), output, key);

        Assert.Equal(Text, Encoding.UTF8.GetString(output.ToArray()));
    }

    [Fact]
    public void Password_hashes_verify()
    {
        Assert.True(Caltrop.Passwords.Verify(Password, PasswordHash));
        Assert.False(Caltrop.Passwords.NeedsRehash(PasswordHash));
    }

    [Fact]
    public void Blind_indexes_are_stable()
    {
        using CaltropKey key = TestKey();

        Assert.Equal(BlindIndex, Caltrop.Hashing.BlindIndex("alice@example.com", key, "users.email"));
    }

    [Fact]
    public void Api_key_checksums_are_stable()
    {
        Assert.True(Caltrop.ApiKeys.IsWellFormed(ApiKey, "acme_live"));
    }

    private static CaltropKey TestKey() => CaltropKey.FromBytes([.. Enumerable.Range(0, 32).Select(i => (byte)i)]);
}
