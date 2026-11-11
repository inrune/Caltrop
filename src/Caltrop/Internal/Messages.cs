using System.Buffers.Binary;
using System.Security.Cryptography;

namespace CaltropSecurity.Internal;

/// <summary>Secret-key messages (kind 0x01): AES-256-GCM with a fresh key derived for every message.</summary>
internal static class SecretKeyMessages
{
    // version(1) kind(1) keyId(4) nonce(24)
    public const int HeaderSize = 2 + Format.KeyIdSize + Format.MessageNonceSize;
    public const int Overhead = HeaderSize + Format.TagSize;

    public static byte[] Encrypt(ReadOnlySpan<byte> plaintext, CaltropKey key, ReadOnlySpan<byte> associatedData)
    {
        ArgumentNullException.ThrowIfNull(key);
        key.ThrowIfDisposed();
        Aead.EnsureSupported();
        Sizes.EnsureFits(plaintext.Length, Overhead);

        byte[] output = new byte[Overhead + plaintext.Length];
        Span<byte> header = output.AsSpan(0, HeaderSize);
        header[0] = Format.Version;
        header[1] = (byte)BlobKind.SecretKeyMessage;
        key.IdBytes.CopyTo(header[2..]);
        Span<byte> nonce = header.Slice(2 + Format.KeyIdSize, Format.MessageNonceSize);
        RandomNumberGenerator.Fill(nonce);

        Span<byte> messageKey = stackalloc byte[Format.KeySize];
        try
        {
            key.Derive(Labels.Message, nonce, messageKey);
            Aead.Seal(
                messageKey,
                nonce[..Format.GcmNonceSize],
                plaintext,
                output.AsSpan(HeaderSize, plaintext.Length),
                output.AsSpan(HeaderSize + plaintext.Length, Format.TagSize),
                header,
                associatedData);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(messageKey);
        }

        return output;
    }

    public static byte[] Decrypt(ReadOnlySpan<byte> data, IReadOnlyList<CaltropKey> keys, ReadOnlySpan<byte> associatedData)
    {
        Errors.ExpectKind(data, BlobKind.SecretKeyMessage);
        if (data.Length < Overhead)
        {
            throw Errors.Truncated();
        }

        Aead.EnsureSupported();
        ReadOnlySpan<byte> header = data[..HeaderSize];
        ReadOnlySpan<byte> keyId = header.Slice(2, Format.KeyIdSize);
        ReadOnlySpan<byte> nonce = header.Slice(2 + Format.KeyIdSize, Format.MessageNonceSize);
        ReadOnlySpan<byte> ciphertext = data[HeaderSize..^Format.TagSize];
        ReadOnlySpan<byte> tag = data[^Format.TagSize..];

        bool anyMatch = false;
        Span<byte> messageKey = stackalloc byte[Format.KeySize];
        try
        {
            foreach (CaltropKey key in keys)
            {
                if (!key.Matches(keyId))
                {
                    continue;
                }

                anyMatch = true;
                key.Derive(Labels.Message, nonce, messageKey);
                byte[] plaintext = new byte[ciphertext.Length];
                if (Aead.TryOpen(messageKey, nonce[..Format.GcmNonceSize], ciphertext, tag, plaintext, header, associatedData))
                {
                    return plaintext;
                }
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(messageKey);
        }

        throw anyMatch ? Errors.AuthenticationFailed("Decryption") : Errors.KeyMismatch(keyId, keys.Count);
    }
}

/// <summary>Password messages (kind 0x02): PBKDF2-HMAC-SHA256 → AES-256-GCM.</summary>
internal static class PasswordMessages
{
    // version(1) kind(1) iterations(4) salt(16) nonce(12)
    public const int HeaderSize = 2 + 4 + PasswordKdf.SaltSize + Format.GcmNonceSize;
    public const int Overhead = HeaderSize + Format.TagSize;

    public static byte[] Encrypt(ReadOnlySpan<byte> plaintext, string password, int iterations)
    {
        PasswordKdf.ValidateNewPassword(password, nameof(password));
        Aead.EnsureSupported();
        Sizes.EnsureFits(plaintext.Length, Overhead);

        byte[] output = new byte[Overhead + plaintext.Length];
        Span<byte> header = output.AsSpan(0, HeaderSize);
        header[0] = Format.Version;
        header[1] = (byte)BlobKind.PasswordMessage;
        BinaryPrimitives.WriteInt32BigEndian(header[2..], iterations);
        Span<byte> salt = header.Slice(6, PasswordKdf.SaltSize);
        Span<byte> nonce = header.Slice(6 + PasswordKdf.SaltSize, Format.GcmNonceSize);
        RandomNumberGenerator.Fill(salt);
        RandomNumberGenerator.Fill(nonce);

        Span<byte> key = stackalloc byte[Format.KeySize];
        try
        {
            PasswordKdf.Derive(password, salt, iterations, key);
            Aead.Seal(key, nonce, plaintext, output.AsSpan(HeaderSize, plaintext.Length), output.AsSpan(HeaderSize + plaintext.Length), header, default);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }

        return output;
    }

    public static byte[] Decrypt(ReadOnlySpan<byte> data, string password)
    {
        ArgumentNullException.ThrowIfNull(password);
        Errors.ExpectKind(data, BlobKind.PasswordMessage);
        if (data.Length < Overhead)
        {
            throw Errors.Truncated();
        }

        Aead.EnsureSupported();
        ReadOnlySpan<byte> header = data[..HeaderSize];
        int iterations = BinaryPrimitives.ReadInt32BigEndian(header[2..]);
        if (iterations is < 1 or > PasswordKdf.MaximumIterations)
        {
            throw Errors.InvalidFormat("the password iteration count in its header is out of range.");
        }

        ReadOnlySpan<byte> salt = header.Slice(6, PasswordKdf.SaltSize);
        ReadOnlySpan<byte> nonce = header.Slice(6 + PasswordKdf.SaltSize, Format.GcmNonceSize);
        Span<byte> key = stackalloc byte[Format.KeySize];
        try
        {
            PasswordKdf.Derive(password, salt, iterations, key);
            byte[] plaintext = new byte[data.Length - Overhead];
            return Aead.TryOpen(key, nonce, data[HeaderSize..^Format.TagSize], data[^Format.TagSize..], plaintext, header, default)
                ? plaintext
                : throw Errors.WrongPassword();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }
}

/// <summary>
/// Public-key messages (kind 0x03): ECIES over P-256. A fresh ephemeral key per message, ECDH with the recipient's
/// encryption key, HKDF-SHA256 to derive the AES-256-GCM key and nonce.
/// </summary>
internal static class PublicKeyMessages
{
    // version(1) kind(1) recipientKeyId(4) ephemeralPoint(65)
    public const int HeaderSize = 2 + Format.KeyIdSize + Format.P256PointSize;
    public const int Overhead = HeaderSize + Format.TagSize;
    private const int OkmSize = Format.KeySize + Format.GcmNonceSize;

    public static byte[] Encrypt(ReadOnlySpan<byte> plaintext, CaltropPublicKey recipient, ReadOnlySpan<byte> associatedData)
    {
        ArgumentNullException.ThrowIfNull(recipient);
        Aead.EnsureSupported();
        Sizes.EnsureFits(plaintext.Length, Overhead);

        byte[] output = new byte[Overhead + plaintext.Length];
        Span<byte> header = output.AsSpan(0, HeaderSize);
        header[0] = Format.Version;
        header[1] = (byte)BlobKind.PublicKeyMessage;
        recipient.IdBytes.CopyTo(header[2..]);

        using var ephemeral = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        ECParameters ephemeralPublic = ephemeral.ExportParameters(includePrivateParameters: false);
        Span<byte> ephemeralPoint = header.Slice(2 + Format.KeyIdSize, Format.P256PointSize);
        ephemeralPoint[0] = 0x04;
        ephemeralPublic.Q.X.AsSpan().CopyTo(ephemeralPoint[1..]);
        ephemeralPublic.Q.Y.AsSpan().CopyTo(ephemeralPoint[(1 + Format.P256CoordinateSize)..]);

        using ECDiffieHellman recipientKey = recipient.CreateEcdh();
        using ECDiffieHellmanPublicKey recipientPublic = recipientKey.PublicKey;
        byte[] shared = ephemeral.DeriveRawSecretAgreement(recipientPublic);

        Span<byte> okm = stackalloc byte[OkmSize];
        try
        {
            DeriveKeyAndNonce(shared, ephemeralPoint, recipient, okm);
            Aead.Seal(
                okm[..Format.KeySize],
                okm[Format.KeySize..],
                plaintext,
                output.AsSpan(HeaderSize, plaintext.Length),
                output.AsSpan(HeaderSize + plaintext.Length),
                header,
                associatedData);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(shared);
            CryptographicOperations.ZeroMemory(okm);
        }

        return output;
    }

    public static byte[] Decrypt(ReadOnlySpan<byte> data, CaltropKeyPair keyPair, ReadOnlySpan<byte> associatedData)
    {
        ArgumentNullException.ThrowIfNull(keyPair);
        keyPair.ThrowIfDisposed();
        Errors.ExpectKind(data, BlobKind.PublicKeyMessage);
        if (data.Length < Overhead)
        {
            throw Errors.Truncated();
        }

        Aead.EnsureSupported();
        ReadOnlySpan<byte> header = data[..HeaderSize];
        ReadOnlySpan<byte> keyId = header.Slice(2, Format.KeyIdSize);
        if (!keyPair.PublicKey.Matches(keyId))
        {
            throw Errors.PublicKeyMismatch(keyId);
        }

        ReadOnlySpan<byte> ephemeralPoint = header.Slice(2 + Format.KeyIdSize, Format.P256PointSize);
        if (ephemeralPoint[0] != 0x04)
        {
            throw Errors.InvalidFormat("the ephemeral public key in its header is not an uncompressed P-256 point.");
        }

        ECDiffieHellman ephemeral;
        try
        {
            // Import validates that the point is on the curve, which blocks invalid-curve attacks.
            ephemeral = ECDiffieHellman.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint
                {
                    X = ephemeralPoint.Slice(1, Format.P256CoordinateSize).ToArray(),
                    Y = ephemeralPoint.Slice(1 + Format.P256CoordinateSize, Format.P256CoordinateSize).ToArray(),
                },
            });
        }
        catch (CryptographicException ex)
        {
            throw new CaltropException(CaltropErrorCode.InvalidFormat, "This is not valid Caltrop data: the ephemeral public key in its header is invalid.", ex);
        }

        byte[] shared;
        using (ephemeral)
        using (ECDiffieHellmanPublicKey ephemeralPublic = ephemeral.PublicKey)
        using (ECDiffieHellman mine = keyPair.CreateEcdh())
        {
            shared = mine.DeriveRawSecretAgreement(ephemeralPublic);
        }

        Span<byte> okm = stackalloc byte[OkmSize];
        try
        {
            DeriveKeyAndNonce(shared, ephemeralPoint, keyPair.PublicKey, okm);
            byte[] plaintext = new byte[data.Length - Overhead];
            return Aead.TryOpen(okm[..Format.KeySize], okm[Format.KeySize..], data[HeaderSize..^Format.TagSize], data[^Format.TagSize..], plaintext, header, associatedData)
                ? plaintext
                : throw Errors.AuthenticationFailed("Decryption");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(shared);
            CryptographicOperations.ZeroMemory(okm);
        }
    }

    /// <summary>HKDF-SHA256(IKM = shared secret, salt = ephemeral point || recipient point, info = label).</summary>
    private static void DeriveKeyAndNonce(ReadOnlySpan<byte> shared, ReadOnlySpan<byte> ephemeralPoint, CaltropPublicKey recipient, Span<byte> okm)
    {
        Span<byte> salt = stackalloc byte[2 * Format.P256PointSize];
        ephemeralPoint.CopyTo(salt);
        recipient.WriteEncryptionPoint(salt[Format.P256PointSize..]);
        HKDF.DeriveKey(HashAlgorithmName.SHA256, shared, okm, salt, Labels.Seal);
    }
}

/// <summary>Signatures (kind 0x07): ECDSA P-256 over SHA-256(label || message).</summary>
internal static class Signatures
{
    // version(1) kind(1) keyId(4) r||s(64)
    public const int SignatureSize = 2 * Format.P256CoordinateSize;
    public const int BlobSize = 2 + Format.KeyIdSize + SignatureSize;

    public static IncrementalHash StartHash()
    {
        var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(Labels.Signature);
        return hash;
    }

    public static string Sign(byte[] digest, CaltropKeyPair keyPair)
    {
        byte[] blob = new byte[BlobSize];
        blob[0] = Format.Version;
        blob[1] = (byte)BlobKind.Signature;
        keyPair.PublicKey.IdBytes.CopyTo(blob.AsSpan(2));
        using (ECDsa ecdsa = keyPair.CreateEcdsa())
        {
            byte[] signature = ecdsa.SignHash(digest, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            signature.CopyTo(blob, 2 + Format.KeyIdSize);
        }

        return System.Buffers.Text.Base64Url.EncodeToString(blob);
    }

    /// <summary>Parses a signature string. Returns <see langword="false"/> for anything that is not a well-formed Caltrop signature.</summary>
    public static bool TryParse(string? signature, out byte[] blob)
    {
        blob = [];
        if (signature is null || !Encodings.TryFromBase64Url(signature, out byte[] bytes) || bytes.Length != BlobSize)
        {
            return false;
        }

        if (bytes[0] != Format.Version || bytes[1] != (byte)BlobKind.Signature)
        {
            return false;
        }

        blob = bytes;
        return true;
    }

    public static bool Verify(byte[] digest, byte[] blob, CaltropPublicKey publicKey)
    {
        if (!publicKey.Matches(blob.AsSpan(2, Format.KeyIdSize)))
        {
            return false;
        }

        using ECDsa ecdsa = publicKey.CreateEcdsa();
        return ecdsa.VerifyHash(digest, blob.AsSpan(2 + Format.KeyIdSize), DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
    }
}

internal static class Sizes
{
    public static void EnsureFits(int plaintextLength, int overhead)
    {
        if (plaintextLength > Array.MaxLength - overhead)
        {
            throw new ArgumentException("The data is too large to encrypt in memory. Use Caltrop.Files to encrypt it as a stream.");
        }
    }
}
