using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using CaltropSecurity.Internal;

namespace CaltropSecurity;

/// <summary>
/// A private/public key pair. Share <see cref="PublicKey"/> freely; keep the key pair itself secret.
/// With it you can decrypt messages sent to your public key and sign data that others verify with your public key.
/// </summary>
/// <example>
/// <code>
/// using var me = CaltropKeyPair.Generate();
/// string publicText  = me.PublicKey.Export();   // "ctpub_..." give this out
/// string privateText = me.ExportPrivateKey();   // "ctprv_..." keep this secret
///
/// string signature = Caltrop.Sign("release v1.2", me);
/// string secret    = Caltrop.Encrypt("hello", me.PublicKey);
/// string plain     = Caltrop.Decrypt(secret, me);
/// </code>
/// </example>
/// <remarks>
/// Contains two NIST P-256 keys: one for encryption (ECDH) and one for signatures (ECDSA), so neither use can
/// weaken the other. Instances are immutable and safe to share between threads. <see cref="Dispose"/> wipes the
/// private keys from memory.
/// </remarks>
public sealed class CaltropKeyPair : IDisposable
{
    /// <summary>Prefix of exported private key strings.</summary>
    public const string Prefix = "ctprv_";

    private const int ScalarSize = Format.P256CoordinateSize;
    private const int PayloadSize = CaltropPublicKey.BlobSize + (2 * ScalarSize);

    /// <summary>encD || sigD.</summary>
    private readonly byte[] _scalars;
    private volatile bool _disposed;

    private CaltropKeyPair(CaltropPublicKey publicKey, ReadOnlySpan<byte> scalars)
    {
        PublicKey = publicKey;
        _scalars = GC.AllocateUninitializedArray<byte>(2 * ScalarSize, pinned: true);
        scalars.CopyTo(_scalars);
    }

    /// <summary>The public half. Safe to share.</summary>
    public CaltropPublicKey PublicKey { get; }

    /// <summary>A short identifier for this key pair (8 hex characters), the same as <c>PublicKey.Id</c>.</summary>
    public string Id => PublicKey.Id;

    /// <summary>Creates a new random key pair.</summary>
    public static CaltropKeyPair Generate()
    {
        using var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        ECParameters enc = ecdh.ExportParameters(includePrivateParameters: true);
        ECParameters sig = ecdsa.ExportParameters(includePrivateParameters: true);
        try
        {
            byte[] blob = [.. enc.Q.X!, .. enc.Q.Y!, .. sig.Q.X!, .. sig.Q.Y!];
            Span<byte> scalars = stackalloc byte[2 * ScalarSize];
            enc.D.AsSpan().CopyTo(scalars);
            sig.D.AsSpan().CopyTo(scalars[ScalarSize..]);
            try
            {
                return new CaltropKeyPair(new CaltropPublicKey(blob), scalars);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(scalars);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(enc.D);
            CryptographicOperations.ZeroMemory(sig.D);
        }
    }

    /// <summary>Loads a key pair from a <c>ctprv_...</c> string made by <see cref="ExportPrivateKey"/>.</summary>
    /// <param name="text">The private key text.</param>
    /// <exception cref="CaltropException">The text is not a valid private key (<see cref="CaltropErrorCode.InvalidKey"/>).</exception>
    public static CaltropKeyPair Parse(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        return TryParseCore(text, out CaltropKeyPair? keyPair, out string error) ? keyPair : throw Errors.InvalidKey(error);
    }

    /// <summary>Like <see cref="Parse(string)"/>, but returns <see langword="false"/> instead of throwing.</summary>
    /// <param name="text">The private key text.</param>
    /// <param name="keyPair">The parsed key pair, or <see langword="null"/>.</param>
    public static bool TryParse([NotNullWhen(true)] string? text, [NotNullWhen(true)] out CaltropKeyPair? keyPair)
    {
        if (text is null)
        {
            keyPair = null;
            return false;
        }

        return TryParseCore(text, out keyPair, out _);
    }

    /// <summary>Writes the private key as a <c>ctprv_...</c> string that <see cref="Parse(string)"/> can read back.</summary>
    /// <remarks>This is a secret. Never log it, commit it or send it to anyone.</remarks>
    public string ExportPrivateKey()
    {
        ThrowIfDisposed();
        byte[] payload = new byte[PayloadSize];
        try
        {
            PublicKey.EncryptionPoint.X.AsSpan().CopyTo(payload);
            PublicKey.EncryptionPoint.Y.AsSpan().CopyTo(payload.AsSpan(ScalarSize));
            PublicKey.SigningPoint.X.AsSpan().CopyTo(payload.AsSpan(2 * ScalarSize));
            PublicKey.SigningPoint.Y.AsSpan().CopyTo(payload.AsSpan(3 * ScalarSize));
            _scalars.CopyTo(payload, CaltropPublicKey.BlobSize);
            return KeyText.Encode(Prefix, payload);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(payload);
        }
    }

    /// <summary>Returns <c>CaltropKeyPair(id)</c>. Never contains the private key, so it is safe to log.</summary>
    public override string ToString() => $"CaltropKeyPair({Id})";

    /// <summary>Wipes the private keys from memory. The key pair cannot be used afterwards.</summary>
    public void Dispose()
    {
        _disposed = true;
        CryptographicOperations.ZeroMemory(_scalars);
    }

    internal void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(_disposed, this);

    internal ECDiffieHellman CreateEcdh()
    {
        ThrowIfDisposed();
        return Import(PublicKey.EncryptionPoint, _scalars.AsSpan(0, ScalarSize), static p => ECDiffieHellman.Create(p));
    }

    internal ECDsa CreateEcdsa()
    {
        ThrowIfDisposed();
        return Import(PublicKey.SigningPoint, _scalars.AsSpan(ScalarSize, ScalarSize), static p => ECDsa.Create(p));
    }

    private static T Import<T>(ECPoint q, ReadOnlySpan<byte> scalar, Func<ECParameters, T> create)
    {
        byte[] d = scalar.ToArray();
        try
        {
            return create(new ECParameters { Curve = ECCurve.NamedCurves.nistP256, Q = q, D = d });
        }
        finally
        {
            CryptographicOperations.ZeroMemory(d);
        }
    }

    private static bool TryParseCore(string text, [NotNullWhen(true)] out CaltropKeyPair? keyPair, out string error)
    {
        keyPair = null;
        if (!KeyText.TryDecode(text, Prefix, PayloadSize, out byte[] payload, out error))
        {
            if (text.AsSpan().Trim().StartsWith(CaltropPublicKey.Prefix, StringComparison.Ordinal))
            {
                error = "This is a public key (ctpub_...). Use CaltropPublicKey.Parse for it. A key pair needs the ctprv_ private key.";
            }

            return false;
        }

        try
        {
            var publicKey = new CaltropPublicKey(payload[..CaltropPublicKey.BlobSize]);
            if (!publicKey.HasValidPoints())
            {
                error = "The private key is damaged: its public part contains an invalid elliptic-curve point.";
                return false;
            }

            var candidate = new CaltropKeyPair(publicKey, payload.AsSpan(CaltropPublicKey.BlobSize));
            if (!candidate.IsConsistent())
            {
                candidate.Dispose();
                error = "The private key is damaged: its private and public parts do not match.";
                return false;
            }

            keyPair = candidate;
            return true;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(payload);
        }
    }

    /// <summary>Proves that each private scalar matches its public point, independent of what the platform checks on import.</summary>
    private bool IsConsistent()
    {
        try
        {
            // Signature made with the private scalar must verify under the stored public point.
            byte[] digest = SHA256.HashData("caltrop/v1/self-test"u8);
            using (ECDsa signer = CreateEcdsa())
            using (ECDsa verifier = PublicKey.CreateEcdsa())
            {
                byte[] signature = signer.SignHash(digest, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
                if (!verifier.VerifyHash(digest, signature, DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
                {
                    return false;
                }
            }

            // ECDH with the private scalar must agree with ECDH against the stored public point.
            using ECDiffieHellman mine = CreateEcdh();
            using ECDiffieHellman minePublic = PublicKey.CreateEcdh();
            using var probe = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            using ECDiffieHellmanPublicKey probePublic = probe.PublicKey;
            using ECDiffieHellmanPublicKey minePublicKey = minePublic.PublicKey;
            byte[] a = mine.DeriveRawSecretAgreement(probePublic);
            byte[] b = probe.DeriveRawSecretAgreement(minePublicKey);
            bool same = CryptographicOperations.FixedTimeEquals(a, b);
            CryptographicOperations.ZeroMemory(a);
            CryptographicOperations.ZeroMemory(b);
            return same;
        }
        catch (Exception ex) when (ex is CryptographicException or PlatformNotSupportedException)
        {
            return false;
        }
    }
}
