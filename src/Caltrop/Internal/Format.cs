namespace CaltropSecurity.Internal;

/// <summary>Wire-format constants shared by every Caltrop blob. See docs/format.md.</summary>
internal static class Format
{
    /// <summary>Byte 0 of every blob.</summary>
    public const byte Version = 0x01;

    public const int KeySize = 32;
    public const int KeyIdSize = 4;
    public const int TagSize = 16;
    public const int GcmNonceSize = 12;

    /// <summary>Random per-message value; the message key is derived from it, the first 12 bytes are the GCM nonce.</summary>
    public const int MessageNonceSize = 24;

    /// <summary>Uncompressed SEC1 P-256 point: 0x04 || X || Y.</summary>
    public const int P256PointSize = 65;
    public const int P256CoordinateSize = 32;
}

/// <summary>Byte 1 of every blob: what kind of data it is.</summary>
internal enum BlobKind : byte
{
    SecretKeyMessage = 0x01,
    PasswordMessage = 0x02,
    PublicKeyMessage = 0x03,
    Token = 0x04,
    SecretKeyStream = 0x05,
    PasswordStream = 0x06,
    Signature = 0x07,
}

/// <summary>
/// Domain-separation labels. Every derived key uses a different label, so a key derived for one purpose can never
/// collide with a key derived for another. None of these is a prefix of another.
/// </summary>
internal static class Labels
{
    public static ReadOnlySpan<byte> KeyId => "caltrop/v1/key-id"u8;
    public static ReadOnlySpan<byte> Message => "caltrop/v1/message:"u8;
    public static ReadOnlySpan<byte> Token => "caltrop/v1/token:"u8;
    public static ReadOnlySpan<byte> Stream => "caltrop/v1/stream:"u8;
    public static ReadOnlySpan<byte> Seal => "caltrop/v1/seal"u8;
    public static ReadOnlySpan<byte> Signature => "caltrop/v1/sign:"u8;
    public static ReadOnlySpan<byte> BlindIndex => "caltrop/v1/blind-index:"u8;
}
