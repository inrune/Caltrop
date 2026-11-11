using System.Buffers.Text;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using CaltropSecurity.Internal;

namespace CaltropSecurity;

public static partial class Caltrop
{
    // ------------------------------------------------------------------------------------------------
    // Public-key encryption
    // ------------------------------------------------------------------------------------------------

    /// <summary>
    /// Encrypts text for the owner of a public key. Only their <see cref="CaltropKeyPair"/> can decrypt it; you do
    /// not need to share any secret with them first.
    /// </summary>
    /// <param name="plaintext">The text to encrypt.</param>
    /// <param name="recipient">The recipient's public key.</param>
    /// <param name="context">Optional text the result is tied to; the same value must be passed when decrypting.</param>
    /// <returns>The encrypted text (Base64Url).</returns>
    /// <remarks>Uses ECIES on P-256: a new temporary key for every message, ECDH, HKDF-SHA256 and AES-256-GCM.</remarks>
    /// <example>
    /// <code>
    /// string secret = Caltrop.Encrypt("meet at noon", alice.PublicKey);
    /// string plain  = Caltrop.Decrypt(secret, alice);   // only Alice's key pair can do this
    /// </code>
    /// </example>
    public static string Encrypt(string plaintext, CaltropPublicKey recipient, string? context = null)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        byte[] bytes = Encodings.Utf8(plaintext, nameof(plaintext));
        try
        {
            return Base64Url.EncodeToString(PublicKeyMessages.Encrypt(bytes, recipient, Encodings.Utf8(context, nameof(context))));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    /// <summary>Encrypts bytes for the owner of a public key.</summary>
    /// <param name="plaintext">The data to encrypt.</param>
    /// <param name="recipient">The recipient's public key.</param>
    /// <param name="context">Optional data the result is tied to; the same value must be passed when decrypting.</param>
    /// <returns>The encrypted data: the plaintext length plus 87 bytes.</returns>
    public static byte[] Encrypt(byte[] plaintext, CaltropPublicKey recipient, byte[]? context = null)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        return PublicKeyMessages.Encrypt(plaintext, recipient, context);
    }

    /// <summary>Decrypts text that was encrypted for your public key.</summary>
    /// <param name="ciphertext">The encrypted text.</param>
    /// <param name="keyPair">Your key pair (the one whose public key was used).</param>
    /// <param name="context">The same context that was passed when encrypting, if any.</param>
    /// <returns>The original text.</returns>
    /// <exception cref="CaltropException">The data was changed, or it was encrypted for a different key pair.</exception>
    public static string Decrypt(string ciphertext, CaltropKeyPair keyPair, string? context = null)
    {
        ArgumentNullException.ThrowIfNull(ciphertext);
        byte[] plaintext = PublicKeyMessages.Decrypt(Encodings.FromBase64Url(ciphertext), keyPair, Encodings.Utf8(context, nameof(context)));
        try
        {
            return Encodings.DecodeUtf8(plaintext);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    /// <summary>Decrypts bytes that were encrypted for your public key.</summary>
    /// <param name="ciphertext">The encrypted data.</param>
    /// <param name="keyPair">Your key pair.</param>
    /// <param name="context">The same context that was passed when encrypting, if any.</param>
    /// <returns>The original data.</returns>
    /// <exception cref="CaltropException">The data was changed, or it was encrypted for a different key pair.</exception>
    public static byte[] Decrypt(byte[] ciphertext, CaltropKeyPair keyPair, byte[]? context = null)
    {
        ArgumentNullException.ThrowIfNull(ciphertext);
        return PublicKeyMessages.Decrypt(ciphertext, keyPair, context);
    }

    // ------------------------------------------------------------------------------------------------
    // Signatures
    // ------------------------------------------------------------------------------------------------

    /// <summary>
    /// Signs text with your private key. Anyone with your public key can check that the text came from you and was
    /// not changed, using <see cref="VerifySignature(string, string?, CaltropPublicKey)"/>.
    /// </summary>
    /// <param name="message">The text to sign.</param>
    /// <param name="keyPair">Your key pair.</param>
    /// <returns>The signature (Base64Url, 94 characters).</returns>
    /// <remarks>ECDSA P-256 with SHA-256. The same message signed twice gives different signatures; both verify.</remarks>
    public static string Sign(string message, CaltropKeyPair keyPair)
    {
        ArgumentNullException.ThrowIfNull(message);
        return Sign(Encodings.Utf8(message, nameof(message)), keyPair);
    }

    /// <summary>Signs bytes with your private key.</summary>
    /// <param name="data">The data to sign.</param>
    /// <param name="keyPair">Your key pair.</param>
    /// <returns>The signature (Base64Url).</returns>
    public static string Sign(byte[] data, CaltropKeyPair keyPair)
    {
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(keyPair);
        keyPair.ThrowIfDisposed();
        using IncrementalHash hash = Signatures.StartHash();
        hash.AppendData(data);
        return Signatures.Sign(hash.GetHashAndReset(), keyPair);
    }

    /// <summary>Signs everything read from a stream (for example a file) with your private key.</summary>
    /// <param name="data">The stream to read to the end. It is not closed.</param>
    /// <param name="keyPair">Your key pair.</param>
    /// <returns>The signature (Base64Url).</returns>
    public static string Sign(Stream data, CaltropKeyPair keyPair)
    {
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(keyPair);
        keyPair.ThrowIfDisposed();
        return Signatures.Sign(HashStream(data), keyPair);
    }

    /// <summary>Checks that <paramref name="message"/> was signed by the owner of <paramref name="publicKey"/> and has not been changed.</summary>
    /// <param name="message">The text that was signed.</param>
    /// <param name="signature">The signature from <see cref="Sign(string, CaltropKeyPair)"/>.</param>
    /// <param name="publicKey">The signer's public key.</param>
    /// <returns>
    /// <see langword="true"/> if the signature is genuine. <see langword="false"/> for anything else, including a
    /// changed message, a damaged or missing signature, or a signature made by a different key.
    /// </returns>
    public static bool VerifySignature(string message, [NotNullWhen(true)] string? signature, CaltropPublicKey publicKey)
    {
        ArgumentNullException.ThrowIfNull(message);
        return VerifySignature(Encodings.Utf8(message, nameof(message)), signature, publicKey);
    }

    /// <summary>Checks a signature over bytes.</summary>
    /// <param name="data">The data that was signed.</param>
    /// <param name="signature">The signature.</param>
    /// <param name="publicKey">The signer's public key.</param>
    /// <returns><see langword="true"/> only if the signature is genuine.</returns>
    public static bool VerifySignature(byte[] data, [NotNullWhen(true)] string? signature, CaltropPublicKey publicKey)
    {
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(publicKey);
        if (!Signatures.TryParse(signature, out byte[] blob))
        {
            return false;
        }

        using IncrementalHash hash = Signatures.StartHash();
        hash.AppendData(data);
        return Signatures.Verify(hash.GetHashAndReset(), blob, publicKey);
    }

    /// <summary>Checks a signature over everything read from a stream (for example a file).</summary>
    /// <param name="data">The stream to read to the end. It is not closed.</param>
    /// <param name="signature">The signature.</param>
    /// <param name="publicKey">The signer's public key.</param>
    /// <returns><see langword="true"/> only if the signature is genuine.</returns>
    public static bool VerifySignature(Stream data, [NotNullWhen(true)] string? signature, CaltropPublicKey publicKey)
    {
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(publicKey);
        return Signatures.TryParse(signature, out byte[] blob) && Signatures.Verify(HashStream(data), blob, publicKey);
    }

    private static byte[] HashStream(Stream data)
    {
        using IncrementalHash hash = Signatures.StartHash();
        byte[] buffer = new byte[81920];
        int read;
        while ((read = data.Read(buffer, 0, buffer.Length)) > 0)
        {
            hash.AppendData(buffer, 0, read);
        }

        return hash.GetHashAndReset();
    }
}
