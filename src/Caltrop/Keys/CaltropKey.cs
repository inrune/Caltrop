using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using CaltropSecurity.Internal;

namespace CaltropSecurity;

/// <summary>
/// A 256-bit secret key for <see cref="Caltrop.Encrypt(string, CaltropKey, string?)"/>, tokens and file encryption.
/// Anyone with the key can decrypt, so store it like a password: in a secret manager or an environment variable,
/// never in source code.
/// </summary>
/// <example>
/// <code>
/// var key = CaltropKey.Generate();
/// string saved = key.Export();               // "ctk_..." store this somewhere safe
/// var sameKey = CaltropKey.Parse(saved);     // load it again later
/// </code>
/// </example>
/// <remarks>
/// Instances are immutable and safe to share between threads. <see cref="Dispose"/> wipes the key from memory;
/// only dispose a key once nothing else is using it.
/// </remarks>
public sealed class CaltropKey : IDisposable
{
    /// <summary>Prefix of exported key strings.</summary>
    public const string Prefix = "ctk_";

    private readonly byte[] _material;
    private readonly byte[] _id;
    private volatile bool _disposed;

    private CaltropKey(ReadOnlySpan<byte> material)
    {
        // Pinned so the GC never copies the key to a new address and leaves the old bytes behind.
        _material = GC.AllocateUninitializedArray<byte>(Format.KeySize, pinned: true);
        material.CopyTo(_material);
        _id = new byte[Format.KeyIdSize];
        HKDF.Expand(HashAlgorithmName.SHA256, _material, _id, Labels.KeyId);
        Id = Convert.ToHexStringLower(_id);
    }

    /// <summary>
    /// A short public identifier for this key (8 hex characters). It is stored in everything the key encrypts, so
    /// Caltrop can pick the right key during rotation and tell you when the wrong key is used. It reveals nothing
    /// about the key.
    /// </summary>
    public string Id { get; }

    internal ReadOnlySpan<byte> IdBytes => _id;

    /// <summary>Creates a new random key.</summary>
    public static CaltropKey Generate()
    {
        Span<byte> buffer = stackalloc byte[Format.KeySize];
        RandomNumberGenerator.Fill(buffer);
        try
        {
            return new CaltropKey(buffer);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
    }

    /// <summary>Creates a key from exactly 32 bytes of random key material (for example from a key vault or HSM).</summary>
    /// <param name="keyMaterial">32 uniformly random bytes. Do not pass a password here; use <see cref="Caltrop.EncryptWithPassword(string, string)"/> for passwords.</param>
    /// <exception cref="ArgumentException"><paramref name="keyMaterial"/> is not 32 bytes long.</exception>
    public static CaltropKey FromBytes(ReadOnlySpan<byte> keyMaterial)
    {
        if (keyMaterial.Length != Format.KeySize)
        {
            throw new ArgumentException($"A Caltrop key must be exactly {Format.KeySize} bytes (256 bits); got {keyMaterial.Length}.", nameof(keyMaterial));
        }

        return new CaltropKey(keyMaterial);
    }

    /// <summary>
    /// Loads a key from text. Accepts a Caltrop key string (<c>ctk_...</c>, from <see cref="Export"/>), or 32 random
    /// bytes written as Base64, Base64Url or hex, for example the output of <c>openssl rand -base64 32</c>.
    /// </summary>
    /// <param name="text">The key text. Surrounding whitespace is ignored.</param>
    /// <exception cref="CaltropException">The text is not a valid key (<see cref="CaltropErrorCode.InvalidKey"/>).</exception>
    public static CaltropKey Parse(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        return TryParseCore(text, out CaltropKey? key, out string error) ? key : throw Errors.InvalidKey(error);
    }

    /// <summary>Like <see cref="Parse(string)"/>, but returns <see langword="false"/> instead of throwing.</summary>
    /// <param name="text">The key text.</param>
    /// <param name="key">The parsed key, or <see langword="null"/>.</param>
    public static bool TryParse([NotNullWhen(true)] string? text, [NotNullWhen(true)] out CaltropKey? key)
    {
        if (text is null)
        {
            key = null;
            return false;
        }

        return TryParseCore(text, out key, out _);
    }

    /// <summary>Writes the key as a <c>ctk_...</c> string (with a built-in checksum) that <see cref="Parse(string)"/> can read back.</summary>
    /// <remarks>The result is the secret key itself. Never log it or put it in source control.</remarks>
    public string Export()
    {
        ThrowIfDisposed();
        return KeyText.Encode(Prefix, _material);
    }

    /// <summary>Returns a copy of the raw 32-byte key material, for storing in systems that want bytes.</summary>
    public byte[] ToBytes()
    {
        ThrowIfDisposed();
        return (byte[])_material.Clone();
    }

    /// <summary>Returns <c>CaltropKey(id)</c>. Never contains the key itself, so it is safe to log.</summary>
    public override string ToString() => $"CaltropKey({Id})";

    /// <summary>Wipes the key from memory. The key cannot be used afterwards.</summary>
    public void Dispose()
    {
        _disposed = true;
        CryptographicOperations.ZeroMemory(_material);
    }

    internal void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(_disposed, this);

    /// <summary>HKDF-Expand(PRK = key, info = label || context).</summary>
    internal void Derive(ReadOnlySpan<byte> label, ReadOnlySpan<byte> context, Span<byte> output)
    {
        ThrowIfDisposed();
        Span<byte> info = stackalloc byte[label.Length + context.Length];
        label.CopyTo(info);
        context.CopyTo(info[label.Length..]);
        HKDF.Expand(HashAlgorithmName.SHA256, _material, output, info);
    }

    internal bool Matches(ReadOnlySpan<byte> keyId) => keyId.SequenceEqual(_id);

    private static bool TryParseCore(string text, [NotNullWhen(true)] out CaltropKey? key, out string error)
    {
        key = null;
        ReadOnlySpan<char> trimmed = text.AsSpan().Trim();
        byte[] material = [];
        try
        {
            if (trimmed.StartsWith(Prefix, StringComparison.Ordinal))
            {
                if (!KeyText.TryDecode(text, Prefix, Format.KeySize, out material, out error))
                {
                    return false;
                }
            }
            else if (!TryDecodeRaw(trimmed, out material))
            {
                error = "Not a valid Caltrop key. Expected a \"ctk_...\" key from CaltropKey.Export(), or 32 random bytes as Base64 or hex.";
                return false;
            }

            key = new CaltropKey(material);
            error = string.Empty;
            return true;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(material);
        }
    }

    private static bool TryDecodeRaw(ReadOnlySpan<char> text, out byte[] material)
    {
        material = [];
        if (text.Length == Format.KeySize * 2 && Encodings.IsHex(text))
        {
            material = Convert.FromHexString(text);
            return true;
        }

        if (text.Length is 43 or 44)
        {
            if ((Encodings.TryFromBase64(text, out byte[] bytes) || Encodings.TryFromBase64Url(text, out bytes)) && bytes.Length == Format.KeySize)
            {
                material = bytes;
                return true;
            }

            CryptographicOperations.ZeroMemory(bytes);
        }

        return false;
    }
}
