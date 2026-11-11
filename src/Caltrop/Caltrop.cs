using System.Buffers.Text;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using CaltropSecurity.Internal;

namespace CaltropSecurity;

/// <summary>
/// The Caltrop API. Everything starts here.
/// </summary>
/// <remarks>
/// <list type="bullet">
/// <item><see cref="Encrypt(string, CaltropKey, string?)"/> and <see cref="Decrypt(string, CaltropKey, string?)"/>: encrypt data with a secret key.</item>
/// <item><see cref="EncryptWithPassword(string, string)"/>: encrypt data with a password.</item>
/// <item><see cref="Encrypt(string, CaltropPublicKey, string?)"/>, <see cref="Sign(string, CaltropKeyPair)"/>: public-key encryption and signatures.</item>
/// <item><see cref="Passwords"/>, <see cref="Tokens"/>, <see cref="TwoFactor"/>, <see cref="Files"/>, <see cref="ApiKeys"/>,
/// <see cref="Webhooks"/>, <see cref="Hashing"/> and <see cref="Random"/> for everything else.</item>
/// </list>
/// Every method is thread-safe. Encrypted output is authenticated: if anyone changes it, decryption throws a
/// <see cref="CaltropException"/> instead of returning wrong data.
/// </remarks>
public static partial class Caltrop
{
    /// <summary>The environment variable the default key is read from: <c>CALTROP_KEY</c>.</summary>
    /// <remarks>It may hold one key, or several separated by commas with the newest first (see <see cref="CaltropKeyRing.Parse(string)"/>).</remarks>
    public const string KeyEnvironmentVariable = "CALTROP_KEY";

    private static CaltropKeyRing? s_defaultKeys;

    /// <summary>
    /// The keys used by the overloads that take no key, such as <see cref="Encrypt(string)"/>. Set them with
    /// <see cref="UseKey(CaltropKey)"/> or <see cref="UseKeys(CaltropKeyRing)"/>; otherwise they are read from the
    /// <c>CALTROP_KEY</c> environment variable the first time they are needed.
    /// </summary>
    /// <exception cref="InvalidOperationException">No key was set and <c>CALTROP_KEY</c> is not set.</exception>
    /// <exception cref="CaltropException"><c>CALTROP_KEY</c> does not contain a valid key.</exception>
    public static CaltropKeyRing DefaultKeys
    {
        get
        {
            CaltropKeyRing? keys = Volatile.Read(ref s_defaultKeys);
            if (keys is not null)
            {
                return keys;
            }

            string? text = Environment.GetEnvironmentVariable(KeyEnvironmentVariable);
            if (string.IsNullOrWhiteSpace(text))
            {
                throw new InvalidOperationException(
                    $"No default Caltrop key is set. Set the {KeyEnvironmentVariable} environment variable to a key " +
                    "(make one with CaltropKey.Generate().Export()), call Caltrop.UseKey(...) when your app starts, " +
                    "or pass a key to this method.");
            }

            try
            {
                keys = CaltropKeyRing.Parse(text);
            }
            catch (CaltropException ex)
            {
                throw new CaltropException(CaltropErrorCode.InvalidKey, $"The {KeyEnvironmentVariable} environment variable does not contain a valid key: {ex.Message}", ex);
            }

            return Interlocked.CompareExchange(ref s_defaultKeys, keys, null) ?? keys;
        }
    }

    /// <summary>Sets the key used by the overloads that take no key. Call it once when your app starts.</summary>
    /// <param name="key">The key.</param>
    /// <remarks>Caltrop keeps using this key object, so do not dispose it while it is the default.</remarks>
    public static void UseKey(CaltropKey key)
    {
        ArgumentNullException.ThrowIfNull(key);
        Volatile.Write(ref s_defaultKeys, new CaltropKeyRing(key));
    }

    /// <summary>Sets the keys used by the overloads that take no key: new data uses the primary key, and data from any key in the ring can be decrypted.</summary>
    /// <param name="keys">The key ring, newest key first.</param>
    /// <remarks>Caltrop keeps using these key objects, so do not dispose them while they are the default.</remarks>
    public static void UseKeys(CaltropKeyRing keys)
    {
        ArgumentNullException.ThrowIfNull(keys);
        Volatile.Write(ref s_defaultKeys, keys);
    }

    /// <summary>Forgets the configured default keys (tests only).</summary>
    internal static void ResetDefaultKeys() => Volatile.Write(ref s_defaultKeys, null);

    // ------------------------------------------------------------------------------------------------
    // Secret-key encryption
    // ------------------------------------------------------------------------------------------------

    /// <summary>Encrypts text with the default key (see <see cref="DefaultKeys"/>).</summary>
    /// <param name="plaintext">The text to encrypt.</param>
    /// <returns>The encrypted text, safe to store in a database, a URL or JSON.</returns>
    /// <example><code>string secret = Caltrop.Encrypt("4111 1111 1111 1111");</code></example>
    public static string Encrypt(string plaintext) => Encrypt(plaintext, DefaultKeys.Primary);

    /// <summary>Decrypts text that was encrypted with the default key (see <see cref="DefaultKeys"/>).</summary>
    /// <param name="ciphertext">Text returned by <see cref="Encrypt(string)"/>.</param>
    /// <returns>The original text.</returns>
    /// <exception cref="CaltropException">The data was changed, or none of the default keys can decrypt it.</exception>
    public static string Decrypt(string ciphertext) => Decrypt(ciphertext, DefaultKeys);

    /// <summary>Encrypts bytes with the default key (see <see cref="DefaultKeys"/>).</summary>
    /// <param name="plaintext">The data to encrypt.</param>
    /// <returns>The encrypted data.</returns>
    public static byte[] Encrypt(byte[] plaintext) => Encrypt(plaintext, DefaultKeys.Primary);

    /// <summary>Decrypts bytes that were encrypted with the default key (see <see cref="DefaultKeys"/>).</summary>
    /// <param name="ciphertext">Data returned by <see cref="Encrypt(byte[])"/>.</param>
    /// <returns>The original data.</returns>
    /// <exception cref="CaltropException">The data was changed, or none of the default keys can decrypt it.</exception>
    public static byte[] Decrypt(byte[] ciphertext) => Decrypt(ciphertext, DefaultKeys);

    /// <summary>Encrypts text with a secret key (AES-256-GCM).</summary>
    /// <param name="plaintext">The text to encrypt.</param>
    /// <param name="key">The secret key.</param>
    /// <param name="context">
    /// Optional. Text that the result is tied to, such as a user id or <c>"users.email"</c>. The same value must be
    /// passed to <see cref="Decrypt(string, CaltropKey, string?)"/>, which stops encrypted values being copied
    /// between rows or fields. It is not secret and is not stored in the output.
    /// </param>
    /// <returns>The encrypted text (Base64Url), safe to store in a database, a URL or JSON.</returns>
    /// <example>
    /// <code>
    /// string secret = Caltrop.Encrypt("4111 1111 1111 1111", key);
    /// string card   = Caltrop.Decrypt(secret, key);
    /// </code>
    /// </example>
    public static string Encrypt(string plaintext, CaltropKey key, string? context = null)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        byte[] bytes = Encodings.Utf8(plaintext, nameof(plaintext));
        try
        {
            return Base64Url.EncodeToString(SecretKeyMessages.Encrypt(bytes, key, Encodings.Utf8(context, nameof(context))));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    /// <summary>Decrypts text made by <see cref="Encrypt(string, CaltropKey, string?)"/>.</summary>
    /// <param name="ciphertext">The encrypted text.</param>
    /// <param name="key">The key it was encrypted with.</param>
    /// <param name="context">The same context that was passed when encrypting, if any.</param>
    /// <returns>The original text.</returns>
    /// <exception cref="CaltropException">
    /// The data was changed or damaged, a different key or context was used, or it is not Caltrop data.
    /// <see cref="CaltropException.ErrorCode"/> says which.
    /// </exception>
    public static string Decrypt(string ciphertext, CaltropKey key, string? context = null) =>
        DecryptText(ciphertext, KeyList.Single(key, nameof(key)), context);

    /// <summary>Decrypts text using whichever key in <paramref name="keys"/> it was encrypted with. Use this during key rotation.</summary>
    /// <param name="ciphertext">The encrypted text.</param>
    /// <param name="keys">The candidate keys, for example a <see cref="CaltropKeyRing"/>.</param>
    /// <param name="context">The same context that was passed when encrypting, if any.</param>
    /// <returns>The original text.</returns>
    /// <exception cref="CaltropException">The data was changed, or none of the keys can decrypt it.</exception>
    public static string Decrypt(string ciphertext, IEnumerable<CaltropKey> keys, string? context = null) =>
        DecryptText(ciphertext, KeyList.From(keys, nameof(keys)), context);

    /// <summary>Encrypts bytes with a secret key (AES-256-GCM).</summary>
    /// <param name="plaintext">The data to encrypt.</param>
    /// <param name="key">The secret key.</param>
    /// <param name="context">Optional data the result is tied to; the same value must be passed when decrypting. Not stored in the output.</param>
    /// <returns>The encrypted data: the plaintext length plus 46 bytes.</returns>
    public static byte[] Encrypt(byte[] plaintext, CaltropKey key, byte[]? context = null)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        return SecretKeyMessages.Encrypt(plaintext, key, context);
    }

    /// <summary>Decrypts bytes made by <see cref="Encrypt(byte[], CaltropKey, byte[])"/>.</summary>
    /// <param name="ciphertext">The encrypted data.</param>
    /// <param name="key">The key it was encrypted with.</param>
    /// <param name="context">The same context that was passed when encrypting, if any.</param>
    /// <returns>The original data.</returns>
    /// <exception cref="CaltropException">The data was changed, a different key or context was used, or it is not Caltrop data.</exception>
    public static byte[] Decrypt(byte[] ciphertext, CaltropKey key, byte[]? context = null)
    {
        ArgumentNullException.ThrowIfNull(ciphertext);
        return SecretKeyMessages.Decrypt(ciphertext, KeyList.Single(key, nameof(key)), context);
    }

    /// <summary>Decrypts bytes using whichever key in <paramref name="keys"/> they were encrypted with.</summary>
    /// <param name="ciphertext">The encrypted data.</param>
    /// <param name="keys">The candidate keys, for example a <see cref="CaltropKeyRing"/>.</param>
    /// <param name="context">The same context that was passed when encrypting, if any.</param>
    /// <returns>The original data.</returns>
    /// <exception cref="CaltropException">The data was changed, or none of the keys can decrypt it.</exception>
    public static byte[] Decrypt(byte[] ciphertext, IEnumerable<CaltropKey> keys, byte[]? context = null)
    {
        ArgumentNullException.ThrowIfNull(ciphertext);
        return SecretKeyMessages.Decrypt(ciphertext, KeyList.From(keys, nameof(keys)), context);
    }

    // ------------------------------------------------------------------------------------------------
    // Password encryption
    // ------------------------------------------------------------------------------------------------

    /// <summary>
    /// Encrypts text with a password. The key is derived with PBKDF2-HMAC-SHA256 (600,000 iterations), which
    /// deliberately takes a fraction of a second so that guessing passwords is slow.
    /// </summary>
    /// <param name="plaintext">The text to encrypt.</param>
    /// <param name="password">The password. Longer is better; anyone who knows it can decrypt.</param>
    /// <returns>The encrypted text (Base64Url).</returns>
    /// <remarks>To store user passwords, do not encrypt them: hash them with <see cref="Passwords.Hash(string)"/>.</remarks>
    public static string EncryptWithPassword(string plaintext, string password)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        byte[] bytes = Encodings.Utf8(plaintext, nameof(plaintext));
        try
        {
            return Base64Url.EncodeToString(PasswordMessages.Encrypt(bytes, password, PasswordKdf.DefaultIterations));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    /// <summary>Decrypts text made by <see cref="EncryptWithPassword(string, string)"/>.</summary>
    /// <param name="ciphertext">The encrypted text.</param>
    /// <param name="password">The password it was encrypted with.</param>
    /// <returns>The original text.</returns>
    /// <exception cref="CaltropException">The password is wrong, or the data was changed.</exception>
    public static string DecryptWithPassword(string ciphertext, string password)
    {
        ArgumentNullException.ThrowIfNull(ciphertext);
        byte[] plaintext = PasswordMessages.Decrypt(Encodings.FromBase64Url(ciphertext), password);
        try
        {
            return Encodings.DecodeUtf8(plaintext);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    /// <summary>Encrypts bytes with a password (PBKDF2-HMAC-SHA256, then AES-256-GCM).</summary>
    /// <param name="plaintext">The data to encrypt.</param>
    /// <param name="password">The password.</param>
    /// <returns>The encrypted data.</returns>
    public static byte[] EncryptWithPassword(byte[] plaintext, string password)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        return PasswordMessages.Encrypt(plaintext, password, PasswordKdf.DefaultIterations);
    }

    /// <summary>Decrypts bytes made by <see cref="EncryptWithPassword(byte[], string)"/>.</summary>
    /// <param name="ciphertext">The encrypted data.</param>
    /// <param name="password">The password it was encrypted with.</param>
    /// <returns>The original data.</returns>
    /// <exception cref="CaltropException">The password is wrong, or the data was changed.</exception>
    public static byte[] DecryptWithPassword(byte[] ciphertext, string password)
    {
        ArgumentNullException.ThrowIfNull(ciphertext);
        return PasswordMessages.Decrypt(ciphertext, password);
    }

    // ------------------------------------------------------------------------------------------------
    // Utilities
    // ------------------------------------------------------------------------------------------------

    /// <summary>
    /// Compares two strings in constant time, so the time taken does not reveal how many characters match.
    /// Use it to compare secrets such as tokens or codes. It does not hide the length.
    /// </summary>
    /// <param name="a">The first string.</param>
    /// <param name="b">The second string.</param>
    /// <returns><see langword="true"/> if both are equal (or both <see langword="null"/>).</returns>
    public static bool SecureEquals(string? a, string? b)
    {
        if (a is null || b is null)
        {
            return a is null && b is null;
        }

        return CryptographicOperations.FixedTimeEquals(MemoryMarshal.AsBytes(a.AsSpan()), MemoryMarshal.AsBytes(b.AsSpan()));
    }

    /// <summary>Compares two byte arrays in constant time. It does not hide the length.</summary>
    /// <param name="a">The first array.</param>
    /// <param name="b">The second array.</param>
    /// <returns><see langword="true"/> if both are equal (or both <see langword="null"/>).</returns>
    public static bool SecureEquals(byte[]? a, byte[]? b)
    {
        if (a is null || b is null)
        {
            return a is null && b is null;
        }

        return CryptographicOperations.FixedTimeEquals(a, b);
    }

    private static string DecryptText(string ciphertext, IReadOnlyList<CaltropKey> keys, string? context)
    {
        ArgumentNullException.ThrowIfNull(ciphertext);
        byte[] plaintext = SecretKeyMessages.Decrypt(Encodings.FromBase64Url(ciphertext), keys, Encodings.Utf8(context, nameof(context)));
        try
        {
            return Encodings.DecodeUtf8(plaintext);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }
}
