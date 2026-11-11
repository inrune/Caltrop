namespace CaltropSecurity.Internal;

/// <summary>Builds the exceptions Caltrop throws, with messages that tell the caller what to do next.</summary>
internal static class Errors
{
    public static CaltropException InvalidFormat(string detail) =>
        new(CaltropErrorCode.InvalidFormat, $"This is not valid Caltrop data: {detail}");

    public static CaltropException Truncated() =>
        InvalidFormat("it is too short. It may have been cut off when it was stored or copied.");

    public static CaltropException NotBase64Url(Exception inner) =>
        new(CaltropErrorCode.InvalidFormat, "This is not valid Caltrop data: it is not Base64Url text. Make sure the whole value was copied and nothing was added to it.", inner);

    public static CaltropException UnsupportedVersion(byte version) =>
        new(CaltropErrorCode.UnsupportedVersion, $"This data uses Caltrop format version {version}, which this version of Caltrop cannot read. Update the Caltrop package.");

    public static CaltropException AuthenticationFailed(string what) =>
        new(CaltropErrorCode.AuthenticationFailed, $"{what} failed: the data was modified or damaged, or the key is wrong.");

    public static CaltropException WrongPassword() =>
        new(CaltropErrorCode.AuthenticationFailed, "Decryption failed: the password is wrong, or the data was modified or damaged.");

    public static CaltropException KeyMismatch(ReadOnlySpan<byte> keyId, int suppliedCount) =>
        new(
            CaltropErrorCode.KeyMismatch,
            suppliedCount == 1
                ? $"This data was encrypted with a different key (key id {Convert.ToHexStringLower(keyId)}). Check that you are using the same key it was encrypted with."
                : $"None of the {suppliedCount} supplied keys matches this data (key id {Convert.ToHexStringLower(keyId)}). Add the key it was encrypted with to the key ring.");

    public static CaltropException PublicKeyMismatch(ReadOnlySpan<byte> keyId) =>
        new(CaltropErrorCode.KeyMismatch, $"This message was encrypted for a different key pair (key id {Convert.ToHexStringLower(keyId)}).");

    public static CaltropException TokenExpired(DateTimeOffset expiredAt) =>
        new(CaltropErrorCode.TokenExpired, $"The token expired at {expiredAt:u}.");

    public static CaltropException InvalidKey(string detail) =>
        new(CaltropErrorCode.InvalidKey, detail);

    /// <summary>Checks bytes 0 and 1 of a blob and throws a helpful error if it is not the expected kind.</summary>
    public static void ExpectKind(ReadOnlySpan<byte> data, BlobKind expected)
    {
        if (data.Length < 2)
        {
            throw Truncated();
        }

        if (data[0] != Format.Version)
        {
            throw data[0] is > Format.Version and < 0x10
                ? UnsupportedVersion(data[0])
                : InvalidFormat("it does not start with a Caltrop header. It may be plain text, or data from another tool.");
        }

        var actual = (BlobKind)data[1];
        if (actual != expected)
        {
            throw new CaltropException(
                CaltropErrorCode.WrongDataType,
                $"Wrong kind of Caltrop data: this is {Describe(actual)}. {HowToOpen(actual)}");
        }
    }

    private static string Describe(BlobKind kind) => kind switch
    {
        BlobKind.SecretKeyMessage => "a message encrypted with a CaltropKey",
        BlobKind.PasswordMessage => "a message encrypted with a password",
        BlobKind.PublicKeyMessage => "a message encrypted for a public key",
        BlobKind.Token => "a Caltrop token",
        BlobKind.SecretKeyStream => "an encrypted file or stream",
        BlobKind.PasswordStream => "a password-encrypted file or stream",
        BlobKind.Signature => "a signature",
        _ => $"an unknown kind of Caltrop data (type 0x{(byte)kind:x2})",
    };

    private static string HowToOpen(BlobKind kind) => kind switch
    {
        BlobKind.SecretKeyMessage => "Use Caltrop.Decrypt(data, key).",
        BlobKind.PasswordMessage => "Use Caltrop.DecryptWithPassword(data, password).",
        BlobKind.PublicKeyMessage => "Use Caltrop.Decrypt(data, keyPair) with the recipient's CaltropKeyPair.",
        BlobKind.Token => "Use Caltrop.Tokens.Validate(token, key).",
        BlobKind.SecretKeyStream => "Use Caltrop.Files.Decrypt(...).",
        BlobKind.PasswordStream => "Use Caltrop.Files.DecryptWithPassword(...).",
        BlobKind.Signature => "Use Caltrop.VerifySignature(message, signature, publicKey).",
        _ => "It may have been made by a newer version of Caltrop.",
    };
}
