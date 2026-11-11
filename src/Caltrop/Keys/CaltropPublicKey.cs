using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using CaltropSecurity.Internal;

namespace CaltropSecurity;

/// <summary>
/// The public half of a <see cref="CaltropKeyPair"/>. It is safe to share: anyone with it can encrypt messages that
/// only the key pair can decrypt, and verify signatures the key pair made.
/// </summary>
/// <example>
/// <code>
/// var publicKey = CaltropPublicKey.Parse("ctpub_...");
/// string secret = Caltrop.Encrypt("for your eyes only", publicKey);
/// bool genuine  = Caltrop.VerifySignature("release v1.2", signature, publicKey);
/// </code>
/// </example>
/// <remarks>
/// Holds two P-256 public keys: one for encryption (ECDH) and one for signatures (ECDSA). Keeping them separate is
/// standard cryptographic hygiene. Instances are immutable and thread-safe.
/// </remarks>
public sealed class CaltropPublicKey : IEquatable<CaltropPublicKey>
{
    /// <summary>Prefix of exported public key strings.</summary>
    public const string Prefix = "ctpub_";

    /// <summary>encX || encY || sigX || sigY.</summary>
    internal const int BlobSize = 4 * Format.P256CoordinateSize;

    private readonly byte[] _blob;
    private readonly byte[] _id;

    internal CaltropPublicKey(byte[] blob)
    {
        _blob = blob;
        _id = SHA256.HashData(blob)[..Format.KeyIdSize];
        Id = Convert.ToHexStringLower(_id);
    }

    /// <summary>A short identifier for this key pair (8 hex characters), also shown on the matching <see cref="CaltropKeyPair"/>.</summary>
    public string Id { get; }

    internal ReadOnlySpan<byte> IdBytes => _id;

    /// <summary>Loads a public key from a <c>ctpub_...</c> string.</summary>
    /// <param name="text">The public key text from <see cref="Export"/>.</param>
    /// <exception cref="CaltropException">The text is not a valid public key (<see cref="CaltropErrorCode.InvalidKey"/>).</exception>
    public static CaltropPublicKey Parse(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        return TryParseCore(text, out CaltropPublicKey? key, out string error) ? key : throw Errors.InvalidKey(error);
    }

    /// <summary>Like <see cref="Parse(string)"/>, but returns <see langword="false"/> instead of throwing.</summary>
    /// <param name="text">The public key text.</param>
    /// <param name="key">The parsed key, or <see langword="null"/>.</param>
    public static bool TryParse([NotNullWhen(true)] string? text, [NotNullWhen(true)] out CaltropPublicKey? key)
    {
        if (text is null)
        {
            key = null;
            return false;
        }

        return TryParseCore(text, out key, out _);
    }

    /// <summary>Writes the public key as a <c>ctpub_...</c> string. Safe to publish.</summary>
    public string Export() => KeyText.Encode(Prefix, _blob);

    /// <summary>Same as <see cref="Export"/>.</summary>
    public override string ToString() => Export();

    /// <inheritdoc />
    public bool Equals([NotNullWhen(true)] CaltropPublicKey? other) => other is not null && _blob.AsSpan().SequenceEqual(other._blob);

    /// <inheritdoc />
    public override bool Equals([NotNullWhen(true)] object? obj) => obj is CaltropPublicKey other && Equals(other);

    /// <inheritdoc />
    public override int GetHashCode() => BinaryPrimitives.ReadInt32LittleEndian(_id);

    /// <summary>Compares two public keys by value.</summary>
    public static bool operator ==(CaltropPublicKey? left, CaltropPublicKey? right) => left is null ? right is null : left.Equals(right);

    /// <summary>Compares two public keys by value.</summary>
    public static bool operator !=(CaltropPublicKey? left, CaltropPublicKey? right) => !(left == right);

    internal bool Matches(ReadOnlySpan<byte> keyId) => keyId.SequenceEqual(_id);

    internal ECPoint EncryptionPoint => Point(0);

    internal ECPoint SigningPoint => Point(2 * Format.P256CoordinateSize);

    /// <summary>The encryption key as an uncompressed SEC1 point (0x04 || X || Y).</summary>
    internal void WriteEncryptionPoint(Span<byte> destination)
    {
        destination[0] = 0x04;
        _blob.AsSpan(0, 2 * Format.P256CoordinateSize).CopyTo(destination[1..]);
    }

    internal ECDiffieHellman CreateEcdh() => ECDiffieHellman.Create(new ECParameters { Curve = ECCurve.NamedCurves.nistP256, Q = EncryptionPoint });

    internal ECDsa CreateEcdsa() => ECDsa.Create(new ECParameters { Curve = ECCurve.NamedCurves.nistP256, Q = SigningPoint });

    private ECPoint Point(int offset) => new()
    {
        X = _blob[offset..(offset + Format.P256CoordinateSize)],
        Y = _blob[(offset + Format.P256CoordinateSize)..(offset + (2 * Format.P256CoordinateSize))],
    };

    private static bool TryParseCore(string text, [NotNullWhen(true)] out CaltropPublicKey? key, out string error)
    {
        key = null;
        if (!KeyText.TryDecode(text, Prefix, BlobSize, out byte[] blob, out error))
        {
            if (text.AsSpan().Trim().StartsWith(CaltropKeyPair.Prefix, StringComparison.Ordinal))
            {
                error = "This is a private key (ctprv_...). Use CaltropKeyPair.Parse for it, and share only its PublicKey.";
            }

            return false;
        }

        var candidate = new CaltropPublicKey(blob);
        if (!candidate.HasValidPoints())
        {
            error = "The public key contains an invalid elliptic-curve point.";
            return false;
        }

        key = candidate;
        return true;
    }

    /// <summary>True if both points are on the P-256 curve and the platform accepts them.</summary>
    internal bool HasValidPoints()
    {
        if (!P256.IsOnCurve(EncryptionPoint) || !P256.IsOnCurve(SigningPoint))
        {
            return false;
        }

        try
        {
            using ECDiffieHellman ecdh = CreateEcdh();
            using ECDsa ecdsa = CreateEcdsa();
            return true;
        }
        catch (Exception ex) when (ex is CryptographicException or PlatformNotSupportedException)
        {
            return false;
        }
    }
}
