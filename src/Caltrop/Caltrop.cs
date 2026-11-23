using System.Buffers.Text;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using CaltropSecurity.Internal;

/// <summary>
/// The Caltrop API. Everything starts here.
/// </summary>
/// <remarks>
/// <list type="bullet">
/// <item><see cref="Encrypt(string)"/> and <see cref="Decrypt(string)"/>: encrypt data. Caltrop makes and keeps the key for you.</item>
/// <item><see cref="Passwords"/>: <see cref="Passwords.Create(string, string[])"/> and <see cref="Passwords.LogIn(string, string, string?)"/> handle user passwords from start to finish.</item>
/// <item><see cref="Secrets"/> and <see cref="Log(string)"/>: keep secrets and a tamper-proof log, with nothing to set up.</item>
/// <item><see cref="EncryptWithPassword(string, string)"/>: encrypt data with a password.</item>
/// <item><see cref="Encrypt(string, CaltropPublicKey, string?)"/>, <see cref="Sign(string, CaltropKeyPair)"/>: public-key encryption and signatures.</item>
/// <item><see cref="Tokens"/>, <see cref="Files"/>, <see cref="ApiKeys"/>, <see cref="Webhooks"/>,
/// <see cref="Hashing"/>, <see cref="Random"/> and <see cref="Safe"/> for everyday security work.</item>
/// <item><see cref="Traps"/>, <see cref="Decoys"/>, <see cref="Tamper"/>, <see cref="CaltropLockout"/>, <see cref="CaltropVault"/>
/// and <see cref="CaltropLog"/> to catch, stop and record attackers.</item>
/// </list>
/// Every method is thread-safe. Encrypted output is authenticated: if anyone changes it, decryption throws a
/// <see cref="CaltropException"/> instead of returning wrong data.
/// </remarks>
public static partial class Caltrop
{
    /// <summary>The environment variable a key can be read from: <c>CALTROP_KEY</c>. Use it on servers and in containers.</summary>
    /// <remarks>It may hold one key, or several separated by commas with the newest first (see <see cref="CaltropKeyRing.Parse(string)"/>).</remarks>
    public const string KeyEnvironmentVariable = "CALTROP_KEY";

    /// <summary>The environment variable that sets <see cref="Folder"/>: <c>CALTROP_FOLDER</c>.</summary>
    public const string FolderEnvironmentVariable = "CALTROP_FOLDER";

    private static CaltropKeyRing? s_defaultKeys;
    private static bool s_defaultKeysFromFolder;
    private static string s_defaultKeysSource = "";
    private static int s_selfChecked;

    /// <summary>
    /// The keys used by everything that does not take a key, such as <see cref="Encrypt(string)"/>. You do not
    /// have to set anything: the first time Caltrop needs a key, it uses, in this order, the key from
    /// <see cref="UseKey(CaltropKey)"/>, the <c>CALTROP_KEY</c> environment variable, or its own key file in
    /// <see cref="Folder"/>, which it creates if needed.
    /// </summary>
    /// <exception cref="InvalidOperationException">There is no key and nowhere to keep one (for example in a container without <c>CALTROP_KEY</c>).</exception>
    /// <exception cref="CaltropException"><c>CALTROP_KEY</c> or the key file does not contain a valid key.</exception>
    public static CaltropKeyRing DefaultKeys
    {
        get
        {
            Traps.ThrowIfLockedDown();
            CaltropKeyRing keys = Volatile.Read(ref s_defaultKeys)
                ?? LoadDefaultKeys(create: true)
                ?? throw new InvalidOperationException(Home.NoKeyMessage());
            CheckSelfOnce();
            return keys;
        }
    }

    /// <summary>
    /// The folder where Caltrop keeps its own things: its key (<c>caltrop.key</c>), <see cref="Secrets"/>
    /// (<c>secrets.vault</c>) and its log (<c>caltrop.log</c>). Back up <c>caltrop.key</c>: without it, data
    /// encrypted with it cannot be read. Several copies of your app can share the folder at once.
    /// </summary>
    /// <remarks>
    /// By default it is a folder for your app in the user's local app data (for example
    /// <c>%LOCALAPPDATA%\Caltrop\MyApp</c> on Windows or <c>~/.local/share/Caltrop/MyApp</c> on Linux), or the
    /// <c>CALTROP_FOLDER</c> environment variable if it is set. In a container there is no default, because the
    /// container's disk is thrown away with it: set <c>CALTROP_KEY</c> or <c>CALTROP_FOLDER</c>. Set this when your
    /// app starts to use another folder, or to <see langword="null"/> to stop Caltrop keeping any files.
    /// </remarks>
    public static string? Folder
    {
        get => Home.Folder;
        set
        {
            Traps.ThrowIfLockedDown();
            Home.Folder = value;
            if (s_defaultKeysFromFolder)
            {
                Volatile.Write(ref s_defaultKeys, null); // the key came from the old folder
                s_defaultKeysFromFolder = false;
            }
        }
    }

    /// <summary>Uses this key for everything that does not take a key, instead of Caltrop's own key. Call it when your app starts.</summary>
    /// <param name="key">The key.</param>
    /// <remarks>Caltrop keeps using this key object, so do not dispose it while it is the default.</remarks>
    public static void UseKey(CaltropKey key)
    {
        ArgumentNullException.ThrowIfNull(key);
        UseKeys(new CaltropKeyRing(key));
    }

    /// <summary>Uses these keys for everything that does not take a key: new data uses the primary key, and data from any key in the ring can be decrypted.</summary>
    /// <param name="keys">The key ring, newest key first.</param>
    /// <remarks>Caltrop keeps using these key objects, so do not dispose them while they are the default.</remarks>
    public static void UseKeys(CaltropKeyRing keys)
    {
        ArgumentNullException.ThrowIfNull(keys);
        Traps.ThrowIfLockedDown();
        Volatile.Write(ref s_defaultKeys, keys);
        s_defaultKeysFromFolder = false;
        s_defaultKeysSource = "set by the app with Caltrop.UseKey";
    }

    /// <summary>Writes an entry to Caltrop's own tamper-proof log (<c>caltrop.log</c> in <see cref="Folder"/>). Alarms are recorded there too.</summary>
    /// <param name="message">What happened, for example <c>"alice changed her password"</c>.</param>
    /// <example><code>Caltrop.Log($"{user} logged in");</code></example>
    public static void Log(string message) => Home.Log().Write(message);

    /// <summary>Checks Caltrop's own log for tampering. A problem sets off the alarm.</summary>
    /// <returns>Whether the log is intact and, if not, the first problem found.</returns>
    public static CaltropLogCheck CheckLog() => Home.Log().Verify();

    /// <summary>Forgets the configured default keys and Caltrop's folder setting (tests only).</summary>
    internal static void ResetDefaultKeys()
    {
        Volatile.Write(ref s_defaultKeys, null);
        s_defaultKeysFromFolder = false;
        s_defaultKeysSource = "";
    }

    /// <summary>
    /// The default keys if there are any, without making a key file, and where they come from in words. Throws if
    /// <c>CALTROP_KEY</c> or the key file is broken. (For <see cref="Status"/>.)
    /// </summary>
    internal static CaltropKeyRing? DescribeDefaultKeys(out string source)
    {
        CaltropKeyRing? keys = Volatile.Read(ref s_defaultKeys) ?? LoadDefaultKeys(create: false);
        source = keys is null ? "" : s_defaultKeysSource;
        return keys;
    }

    /// <summary>
    /// The default keys if there are any, without making a new key file: <see langword="null"/> if none are set, or
    /// Caltrop is locked down. Never throws. Used to recognize decoys, which only exist if a key does.
    /// </summary>
    internal static CaltropKeyRing? TryGetDefaultKeys()
    {
        CheckSelfOnce();
        if (Traps.IsLockedDown)
        {
            return null;
        }

        CaltropKeyRing? keys = Volatile.Read(ref s_defaultKeys);
        if (keys is not null)
        {
            return keys;
        }

        try
        {
            return LoadDefaultKeys(create: false);
        }
        catch (Exception ex) when (ex is CaltropException or IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            return null;
        }
    }

    /// <summary>Reads <c>CALTROP_KEY</c>, or else Caltrop's key file (making one if <paramref name="create"/> is set).</summary>
    private static CaltropKeyRing? LoadDefaultKeys(bool create)
    {
        CaltropKeyRing? keys;
        bool fromFolder = false;
        string? text = Environment.GetEnvironmentVariable(KeyEnvironmentVariable);
        if (!string.IsNullOrWhiteSpace(text))
        {
            try
            {
                keys = CaltropKeyRing.Parse(text);
            }
            catch (CaltropException ex)
            {
                throw new CaltropException(CaltropErrorCode.InvalidKey, $"The {KeyEnvironmentVariable} environment variable does not contain a valid key: {ex.Message}", ex);
            }
        }
        else
        {
            keys = Home.LoadKey(create);
            fromFolder = true;
            if (keys is null)
            {
                return null;
            }
        }

        CaltropKeyRing? existing = Interlocked.CompareExchange(ref s_defaultKeys, keys, null);
        if (existing is not null)
        {
            return existing;
        }

        s_defaultKeysFromFolder = fromFolder;
        s_defaultKeysSource = fromFolder
            ? $"{Path.Combine(Home.Folder ?? "", Home.KeyFileName)} (back this file up)"
            : $"the {KeyEnvironmentVariable} environment variable";
        return keys;
    }

    /// <summary>
    /// The first time Caltrop is used for anything with a key or password, checks that Caltrop.dll has not been
    /// changed (see <see cref="Tamper.CheckCaltrop"/>). A changed DLL sets off the alarm, which is recorded in the log.
    /// It runs where a key is used, never while a key is being made, so the alarm can always reach the log.
    /// </summary>
    internal static void CheckSelfOnce()
    {
        if (Volatile.Read(ref s_selfChecked) == 0 && Interlocked.Exchange(ref s_selfChecked, 1) == 0)
        {
            Tamper.CheckCaltrop();
        }
    }

    /// <summary><see langword="true"/> once <see cref="CheckSelfOnce"/> has run (tests only).</summary>
    internal static bool SelfCheckDone => Volatile.Read(ref s_selfChecked) != 0;

    /// <summary>Lets <see cref="CheckSelfOnce"/> run again (tests only).</summary>
    internal static void ResetSelfCheckForTests() => Volatile.Write(ref s_selfChecked, 0);

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
