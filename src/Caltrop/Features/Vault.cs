using System.Buffers.Binary;
using System.Security.Cryptography;
using CaltropSecurity.Internal;

/// <summary>
/// A secure vault: named secrets (passwords, API keys, tokens, any text or bytes) kept in one encrypted file,
/// unlocked with a password or a <see cref="CaltropKey"/>. Every change is saved straight away.
/// </summary>
/// <example>
/// <code>
/// using (var vault = CaltropVault.Create("secrets.vault", masterPassword))
/// {
///     vault.Set("db-password", "hunter2");
///     vault.Set("stripe-key", "sk_live_...");
/// }
///
/// using var opened = CaltropVault.Open("secrets.vault", masterPassword);
/// string? db = opened.Get("db-password");
/// </code>
/// </example>
/// <remarks>
/// <para>
/// The file is AES-256-GCM encrypted. With a password, the key is derived with PBKDF2 (600,000 iterations), so
/// guessing is slow, but a short password can still be guessed: ask for a long one. A wrong password and a changed
/// file give the same error, so nobody learns which. A vault locked with a key sets off a
/// <see cref="CaltropAlarmKind.Tampering"/> alarm if its file was changed.
/// </para>
/// <para>
/// Several programs, or several copies of your app, can use the same vault at once: each sees the others' changes,
/// and no change is lost. (Caltrop keeps a small <c>.lock</c> file next to the vault for this.) Saves go through a
/// temporary file, so a crash never leaves a half-written vault. Open secrets live in memory until
/// <see cref="Dispose"/> (or a lockdown) wipes them.
/// </para>
/// </remarks>
public sealed class CaltropVault : IDisposable, IWipeable
{
    private const byte PasswordMode = 0x01;
    private const byte KeyMode = 0x02;
    private const int MaxNameLength = 256;
    private const int MaxFileSize = 64 * 1024 * 1024;
    private const int PasswordHeaderSize = 3 + 4 + PasswordKdf.SaltSize + Format.MessageNonceSize;
    private const int KeyHeaderSize = 3 + Format.KeyIdSize + Format.MessageNonceSize;

    private readonly Lock _gate = new();
    private readonly byte[] _masterKey = GC.AllocateUninitializedArray<byte>(Format.KeySize, pinned: true);
    private readonly byte _mode;
    private readonly byte[] _keyId;
    private Dictionary<string, byte[]> _entries = new(StringComparer.Ordinal);
    private int _iterations;
    private byte[] _salt;

    /// <summary>The random nonce of the saved version in memory. A different one in the file means someone else saved since.</summary>
    private byte[] _version = [];

    /// <summary>A saved version that could not be loaded, and why, so the error (and its alarm) is not repeated on every call.</summary>
    private byte[]? _badVersion;
    private CaltropException? _badVersionError;
    private volatile bool _disposed;

    private CaltropVault(string path, byte mode, ReadOnlySpan<byte> masterKey, int iterations, byte[] salt, byte[] keyId)
    {
        Path = path;
        _mode = mode;
        masterKey.CopyTo(_masterKey);
        _iterations = iterations;
        _salt = salt;
        _keyId = keyId;
        Wipeables.Register(this);
    }

    /// <summary>The full path of the vault file.</summary>
    public string Path { get; }

    /// <summary>The number of secrets in the vault.</summary>
    public int Count
    {
        get
        {
            lock (_gate)
            {
                ThrowIfUnusable();
                Refresh();
                return _entries.Count;
            }
        }
    }

    /// <summary>The names of the secrets, sorted.</summary>
    public IReadOnlyList<string> Names
    {
        get
        {
            lock (_gate)
            {
                ThrowIfUnusable();
                Refresh();
                return [.. _entries.Keys.Order(StringComparer.Ordinal)];
            }
        }
    }

    private int HeaderSize => _mode == PasswordMode ? PasswordHeaderSize : KeyHeaderSize;

    /// <summary>Creates a new, empty vault file locked with a password.</summary>
    /// <param name="path">Where to create it. The file must not exist yet; its folder is created if needed.</param>
    /// <param name="password">The password. Make it long: anyone who has the file can try passwords.</param>
    /// <returns>The open vault. Dispose it when you are done.</returns>
    /// <exception cref="IOException">A file already exists at <paramref name="path"/>.</exception>
    public static CaltropVault Create(string path, string password)
    {
        PasswordKdf.ValidateNewPassword(password, nameof(password));
        string fullPath = NewFilePath(path);
        byte[] salt = RandomNumberGenerator.GetBytes(PasswordKdf.SaltSize);
        Span<byte> master = stackalloc byte[Format.KeySize];
        try
        {
            PasswordKdf.Derive(password, salt, PasswordKdf.DefaultIterations, master);
            return SaveNew(new CaltropVault(fullPath, PasswordMode, master, PasswordKdf.DefaultIterations, salt, []));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(master);
        }
    }

    /// <summary>Creates a new, empty vault file locked with a key.</summary>
    /// <param name="path">Where to create it. The file must not exist yet; its folder is created if needed.</param>
    /// <param name="key">The key. The same key opens it again.</param>
    /// <returns>The open vault. Dispose it when you are done.</returns>
    /// <exception cref="IOException">A file already exists at <paramref name="path"/>.</exception>
    public static CaltropVault Create(string path, CaltropKey key)
    {
        ArgumentNullException.ThrowIfNull(key);
        string fullPath = NewFilePath(path);
        Span<byte> master = stackalloc byte[Format.KeySize];
        try
        {
            DeriveKeyModeMaster(key, master);
            return SaveNew(new CaltropVault(fullPath, KeyMode, master, 0, [], key.IdBytes.ToArray()));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(master);
        }
    }

    /// <summary>Opens a vault file locked with a password.</summary>
    /// <param name="path">The vault file.</param>
    /// <param name="password">Its password.</param>
    /// <returns>The open vault. Dispose it when you are done.</returns>
    /// <exception cref="CaltropException">The password is wrong or the file was changed (<see cref="CaltropErrorCode.AuthenticationFailed"/>).</exception>
    public static CaltropVault Open(string path, string password)
    {
        ArgumentNullException.ThrowIfNull(password);
        (string fullPath, byte[] data) = ReadVaultFile(path, PasswordMode);
        int iterations = BinaryPrimitives.ReadInt32BigEndian(data.AsSpan(3));
        if (iterations is < 1 or > PasswordKdf.MaximumIterations)
        {
            throw Errors.InvalidFormat("the vault's password iteration count is out of range.");
        }

        byte[] salt = data.AsSpan(7, PasswordKdf.SaltSize).ToArray();
        Span<byte> master = stackalloc byte[Format.KeySize];
        try
        {
            PasswordKdf.Derive(password, salt, iterations, master);
            var vault = new CaltropVault(fullPath, PasswordMode, master, iterations, salt, []);
            vault.LoadFirst(data, onFailure: Errors.WrongPassword);
            return vault;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(master);
        }
    }

    /// <summary>Opens a vault file locked with a key.</summary>
    /// <param name="path">The vault file.</param>
    /// <param name="key">The key it was created with.</param>
    /// <returns>The open vault. Dispose it when you are done.</returns>
    /// <exception cref="CaltropException">The key is wrong (<see cref="CaltropErrorCode.KeyMismatch"/>), or the file was changed (<see cref="CaltropErrorCode.AuthenticationFailed"/>).</exception>
    public static CaltropVault Open(string path, CaltropKey key)
    {
        ArgumentNullException.ThrowIfNull(key);
        (string fullPath, byte[] data) = ReadVaultFile(path, KeyMode);
        ReadOnlySpan<byte> keyId = data.AsSpan(3, Format.KeyIdSize);
        if (!key.Matches(keyId))
        {
            throw Errors.KeyMismatch(keyId, 1);
        }

        Span<byte> master = stackalloc byte[Format.KeySize];
        try
        {
            DeriveKeyModeMaster(key, master);
            var vault = new CaltropVault(fullPath, KeyMode, master, 0, [], keyId.ToArray());
            vault.LoadFirst(data, onFailure: () => vault.Tampered(raiseAlarm: true));
            return vault;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(master);
        }
    }

    /// <summary>Opens a vault file locked with whichever key in <paramref name="keys"/> it was created with. Useful after rotating keys.</summary>
    /// <param name="path">The vault file.</param>
    /// <param name="keys">The candidate keys, for example <see cref="Caltrop.DefaultKeys"/>.</param>
    /// <returns>The open vault. Dispose it when you are done.</returns>
    /// <exception cref="CaltropException">None of the keys matches (<see cref="CaltropErrorCode.KeyMismatch"/>), or the file was changed.</exception>
    public static CaltropVault Open(string path, CaltropKeyRing keys)
    {
        ArgumentNullException.ThrowIfNull(keys);
        (_, byte[] data) = ReadVaultFile(path, KeyMode);
        ReadOnlySpan<byte> keyId = data.AsSpan(3, Format.KeyIdSize);
        foreach (CaltropKey key in keys)
        {
            if (key.Matches(keyId))
            {
                return Open(path, key);
            }
        }

        throw Errors.KeyMismatch(keyId, keys.Count);
    }

    /// <summary><see langword="true"/> if the vault has a secret with this name.</summary>
    /// <param name="name">The secret's name.</param>
    public bool Contains(string name)
    {
        ArgumentNullException.ThrowIfNull(name);
        lock (_gate)
        {
            ThrowIfUnusable();
            Refresh();
            return _entries.ContainsKey(name);
        }
    }

    /// <summary>Stores a text secret (replacing any with the same name) and saves the vault.</summary>
    /// <param name="name">The secret's name, 1 to 256 characters. Names are case-sensitive.</param>
    /// <param name="value">The secret.</param>
    public void Set(string name, string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        byte[] bytes = Encodings.Utf8(value, nameof(value));
        try
        {
            Set(name, bytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    /// <summary>Stores a secret as bytes (replacing any with the same name) and saves the vault.</summary>
    /// <param name="name">The secret's name, 1 to 256 characters. Names are case-sensitive.</param>
    /// <param name="value">The secret. Caltrop keeps its own copy.</param>
    public void Set(string name, byte[] value)
    {
        ValidateName(name);
        ArgumentNullException.ThrowIfNull(value);
        byte[] copy = GC.AllocateUninitializedArray<byte>(value.Length, pinned: true);
        value.CopyTo(copy, 0);
        lock (_gate)
        {
            ThrowIfUnusable();
            using (SharedFile.Lock(Path))
            {
                Refresh();
                _entries.TryGetValue(name, out byte[]? old);
                _entries[name] = copy;
                try
                {
                    Save();
                }
                catch
                {
                    if (old is null)
                    {
                        _entries.Remove(name);
                    }
                    else
                    {
                        _entries[name] = old;
                        old = null;
                    }

                    CryptographicOperations.ZeroMemory(copy);
                    throw;
                }
                finally
                {
                    if (old is not null)
                    {
                        CryptographicOperations.ZeroMemory(old);
                    }
                }
            }
        }
    }

    /// <summary>Reads a text secret.</summary>
    /// <param name="name">The secret's name.</param>
    /// <returns>The secret, or <see langword="null"/> if there is none with this name.</returns>
    public string? Get(string name)
    {
        ArgumentNullException.ThrowIfNull(name);
        lock (_gate)
        {
            ThrowIfUnusable();
            Refresh();
            return _entries.TryGetValue(name, out byte[]? value) ? Encodings.DecodeUtf8(value) : null;
        }
    }

    /// <summary>Reads a secret as bytes.</summary>
    /// <param name="name">The secret's name.</param>
    /// <returns>A copy of the secret (wipe it when done), or <see langword="null"/> if there is none with this name.</returns>
    public byte[]? GetBytes(string name)
    {
        ArgumentNullException.ThrowIfNull(name);
        lock (_gate)
        {
            ThrowIfUnusable();
            Refresh();
            return _entries.TryGetValue(name, out byte[]? value) ? (byte[])value.Clone() : null;
        }
    }

    /// <summary>Deletes a secret and saves the vault.</summary>
    /// <param name="name">The secret's name.</param>
    /// <returns><see langword="true"/> if it existed.</returns>
    public bool Remove(string name)
    {
        ArgumentNullException.ThrowIfNull(name);
        lock (_gate)
        {
            ThrowIfUnusable();
            using (SharedFile.Lock(Path))
            {
                Refresh();
                if (!_entries.Remove(name, out byte[]? old))
                {
                    return false;
                }

                try
                {
                    Save();
                }
                catch
                {
                    _entries[name] = old;
                    throw;
                }

                CryptographicOperations.ZeroMemory(old);
                return true;
            }
        }
    }

    /// <summary>Changes the password of a password-locked vault and saves it.</summary>
    /// <param name="newPassword">The new password.</param>
    /// <exception cref="InvalidOperationException">The vault is locked with a key, not a password.</exception>
    public void ChangePassword(string newPassword)
    {
        PasswordKdf.ValidateNewPassword(newPassword, nameof(newPassword));
        if (_mode != PasswordMode)
        {
            throw new InvalidOperationException("This vault is locked with a key, not a password.");
        }

        ThrowIfUnusable();
        byte[] salt = RandomNumberGenerator.GetBytes(PasswordKdf.SaltSize);
        Span<byte> master = stackalloc byte[Format.KeySize];
        Span<byte> previous = stackalloc byte[Format.KeySize];
        try
        {
            // The slow part comes first, so nobody waits for it.
            PasswordKdf.Derive(newPassword, salt, PasswordKdf.DefaultIterations, master);
            lock (_gate)
            {
                ThrowIfUnusable();
                using (SharedFile.Lock(Path))
                {
                    Refresh();
                    (byte[] oldSalt, int oldIterations) = (_salt, _iterations);
                    _masterKey.CopyTo(previous);
                    master.CopyTo(_masterKey);
                    (_salt, _iterations) = (salt, PasswordKdf.DefaultIterations);
                    try
                    {
                        Save();
                    }
                    catch
                    {
                        previous.CopyTo(_masterKey);
                        (_salt, _iterations) = (oldSalt, oldIterations);
                        throw;
                    }
                }
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(master);
            CryptographicOperations.ZeroMemory(previous);
        }
    }

    /// <summary>Wipes the vault's key and every secret from memory. The file stays as it is.</summary>
    public void Dispose()
    {
        lock (_gate)
        {
            WipeMemory();
        }
    }

    void IWipeable.Wipe() => WipeMemory();

    private void WipeMemory()
    {
        _disposed = true;
        CryptographicOperations.ZeroMemory(_masterKey);
        Wipe(_entries);
    }

    private static void Wipe(Dictionary<string, byte[]> entries)
    {
        foreach (byte[] value in entries.Values)
        {
            CryptographicOperations.ZeroMemory(value);
        }

        entries.Clear();
    }

    private void ThrowIfUnusable()
    {
        Caltrop.Traps.ThrowIfLockedDown();
        ObjectDisposedException.ThrowIf(_disposed, this);
    }

    private static CaltropVault SaveNew(CaltropVault vault)
    {
        try
        {
            SharedFile.CreateFolderFor(vault.Path);
            using (SharedFile.Lock(vault.Path))
            {
                if (File.Exists(vault.Path))
                {
                    throw AlreadyExists(vault.Path); // another program made it a moment ago
                }

                vault.Save(replace: false);
            }

            return vault;
        }
        catch
        {
            vault.Dispose();
            throw;
        }
    }

    private static void DeriveKeyModeMaster(CaltropKey key, Span<byte> master) => key.Derive(Labels.Vault, "master"u8, master);

    private static string NewFilePath(string path)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        string fullPath = System.IO.Path.GetFullPath(path);
        return File.Exists(fullPath) ? throw AlreadyExists(fullPath) : fullPath;
    }

    private static IOException AlreadyExists(string path) => new($"A file already exists at {path}. Use CaltropVault.Open to open it.");

    private static (string FullPath, byte[] Data) ReadVaultFile(string path, byte expectedMode)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        Caltrop.Traps.ThrowIfLockedDown();
        string fullPath = System.IO.Path.GetFullPath(path);
        if (!File.Exists(fullPath))
        {
            throw new FileNotFoundException($"There is no vault at {fullPath}.", fullPath);
        }

        using FileStream file = SharedFile.OpenRead(fullPath);
        byte[] data = ReadAll(file);
        Validate(data, expectedMode);
        return (fullPath, data);
    }

    private static byte[] ReadAll(FileStream file)
    {
        if (file.Length > MaxFileSize)
        {
            throw Errors.InvalidFormat("the vault file is too large.");
        }

        byte[] data = new byte[file.Length];
        file.Position = 0;
        file.ReadExactly(data);
        return data;
    }

    /// <summary>Checks that this is a whole vault file, locked the expected way.</summary>
    private static void Validate(byte[] data, byte expectedMode)
    {
        Errors.ExpectKind(data, BlobKind.Vault);
        if (data.Length < 3)
        {
            throw Errors.Truncated();
        }

        if (data[2] != expectedMode)
        {
            throw new CaltropException(
                CaltropErrorCode.WrongDataType,
                data[2] == PasswordMode
                    ? "This vault is locked with a password. Use CaltropVault.Open(path, password)."
                    : "This vault is locked with a key. Use CaltropVault.Open(path, key).");
        }

        int headerSize = expectedMode == PasswordMode ? PasswordHeaderSize : KeyHeaderSize;
        if (data.Length < headerSize + Format.TagSize)
        {
            throw Errors.Truncated();
        }
    }

    private void LoadFirst(byte[] data, Func<CaltropException> onFailure)
    {
        try
        {
            _entries = Decrypt(data) ?? throw onFailure();
            _version = data.AsSpan(HeaderSize - Format.MessageNonceSize, Format.MessageNonceSize).ToArray();
        }
        catch
        {
            WipeMemory();
            throw;
        }
    }

    /// <summary>
    /// If someone else (another program, or another <see cref="CaltropVault"/>) saved the file since this vault last
    /// read or saved it, loads their version. If the file was deleted, keeps what is in memory: the next change
    /// saves it again.
    /// </summary>
    private void Refresh()
    {
        byte[] data;
        using (FileStream? file = SharedFile.TryOpenRead(Path))
        {
            if (file is null)
            {
                return;
            }

            Span<byte> version = stackalloc byte[Format.MessageNonceSize];
            if (file.Length >= HeaderSize)
            {
                file.Position = HeaderSize - Format.MessageNonceSize;
                file.ReadExactly(version);
                if (version.SequenceEqual(_version))
                {
                    return; // unchanged: the usual case
                }

                if (_badVersion is not null && version.SequenceEqual(_badVersion))
                {
                    throw new CaltropException(_badVersionError!.ErrorCode, _badVersionError.Message);
                }
            }

            data = ReadAll(file);
        }

        byte[] newVersion = data.Length >= HeaderSize ? data.AsSpan(HeaderSize - Format.MessageNonceSize, Format.MessageNonceSize).ToArray() : [];
        Dictionary<string, byte[]>? entries;
        try
        {
            Validate(data, _mode);
            CheckSameLock(data);
            entries = Decrypt(data);
        }
        catch (CaltropException ex)
        {
            (_badVersion, _badVersionError) = (newVersion, ex);
            throw;
        }

        if (entries is null)
        {
            // Remembered before the alarm goes off, so an alarm handler that reads this vault gets the error, not another alarm.
            CaltropException error = Tampered(raiseAlarm: false);
            (_badVersion, _badVersionError) = (newVersion, error);
            Tampered(raiseAlarm: true);
            throw error;
        }

        Wipe(_entries);
        _entries = entries;
        _version = newVersion;
    }

    /// <summary>Checks that a newer version of the file is still locked with this vault's key or password.</summary>
    private void CheckSameLock(byte[] data)
    {
        if (_mode == KeyMode)
        {
            ReadOnlySpan<byte> keyId = data.AsSpan(3, Format.KeyIdSize);
            if (!keyId.SequenceEqual(_keyId))
            {
                throw Errors.KeyMismatch(keyId, 1);
            }
        }
        else if (BinaryPrimitives.ReadInt32BigEndian(data.AsSpan(3)) != _iterations || !data.AsSpan(7, PasswordKdf.SaltSize).SequenceEqual(_salt))
        {
            throw new CaltropException(
                CaltropErrorCode.AuthenticationFailed,
                $"The password of the vault {Path} was changed by another program. Open it again with the new password.");
        }
    }

    /// <summary>The error for a vault file that was changed by something other than Caltrop. A vault locked with a key can also set off the alarm.</summary>
    private CaltropException Tampered(bool raiseAlarm)
    {
        if (_mode == KeyMode)
        {
            if (raiseAlarm)
            {
                Tampering.Raise("Vault", $"The vault {Path} failed its integrity check: the file was changed.", Path);
            }

            return Errors.AuthenticationFailed("Opening the vault");
        }

        return new CaltropException(CaltropErrorCode.AuthenticationFailed, $"The vault {Path} was changed by something other than Caltrop, or is damaged.");
    }

    /// <summary>Decrypts a vault file. Returns <see langword="null"/> if it fails its integrity check.</summary>
    private Dictionary<string, byte[]>? Decrypt(byte[] data)
    {
        int headerSize = HeaderSize;
        ReadOnlySpan<byte> header = data.AsSpan(0, headerSize);
        ReadOnlySpan<byte> nonce = header[^Format.MessageNonceSize..];
        byte[] plaintext = GC.AllocateUninitializedArray<byte>(data.Length - headerSize - Format.TagSize, pinned: true);
        Span<byte> fileKey = stackalloc byte[Format.KeySize];
        try
        {
            DeriveFileKey(nonce, fileKey);
            return Aead.TryOpen(fileKey, nonce[..Format.GcmNonceSize], data.AsSpan(headerSize, plaintext.Length), data.AsSpan(data.Length - Format.TagSize), plaintext, header, default)
                ? ParseEntries(plaintext)
                : null;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(fileKey);
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    private void Save(bool replace = true)
    {
        int headerSize = HeaderSize;
        byte[] plaintext = SerializeEntries();
        byte[] output = new byte[headerSize + plaintext.Length + Format.TagSize];
        Span<byte> header = output.AsSpan(0, headerSize);
        header[0] = Format.Version;
        header[1] = (byte)BlobKind.Vault;
        header[2] = _mode;
        if (_mode == PasswordMode)
        {
            BinaryPrimitives.WriteInt32BigEndian(header[3..], _iterations);
            _salt.CopyTo(header[7..]);
        }
        else
        {
            _keyId.CopyTo(header[3..]);
        }

        Span<byte> nonce = header[^Format.MessageNonceSize..];
        RandomNumberGenerator.Fill(nonce);
        Span<byte> fileKey = stackalloc byte[Format.KeySize];
        try
        {
            DeriveFileKey(nonce, fileKey);
            Aead.Seal(fileKey, nonce[..Format.GcmNonceSize], plaintext, output.AsSpan(headerSize, plaintext.Length), output.AsSpan(headerSize + plaintext.Length), header, default);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(fileKey);
            CryptographicOperations.ZeroMemory(plaintext);
        }

        SharedFile.WriteAtomically(Path, output, replace);
        _version = nonce.ToArray();
    }

    private void DeriveFileKey(ReadOnlySpan<byte> nonce, Span<byte> fileKey)
    {
        Span<byte> info = stackalloc byte[Labels.Vault.Length + nonce.Length];
        Labels.Vault.CopyTo(info);
        nonce.CopyTo(info[Labels.Vault.Length..]);
        HKDF.Expand(HashAlgorithmName.SHA256, _masterKey, fileKey, info);
    }

    /// <summary>count(4) then, for each entry in name order: nameLength(2) name valueLength(4) value. Big-endian.</summary>
    private byte[] SerializeEntries()
    {
        var names = _entries.Keys.Order(StringComparer.Ordinal).ToArray();
        var encodedNames = names.Select(name => Encodings.Utf8(name, nameof(name))).ToArray();
        long size = 4;
        for (int i = 0; i < names.Length; i++)
        {
            size += 2 + encodedNames[i].Length + 4 + _entries[names[i]].Length;
        }

        if (size > MaxFileSize)
        {
            throw new InvalidOperationException("The vault is full: it can hold up to 64 MiB of secrets.");
        }

        byte[] buffer = GC.AllocateUninitializedArray<byte>((int)size, pinned: true);
        Span<byte> span = buffer;
        BinaryPrimitives.WriteInt32BigEndian(span, names.Length);
        int offset = 4;
        for (int i = 0; i < names.Length; i++)
        {
            byte[] value = _entries[names[i]];
            BinaryPrimitives.WriteUInt16BigEndian(span[offset..], (ushort)encodedNames[i].Length);
            encodedNames[i].CopyTo(span[(offset + 2)..]);
            offset += 2 + encodedNames[i].Length;
            BinaryPrimitives.WriteInt32BigEndian(span[offset..], value.Length);
            value.CopyTo(span[(offset + 4)..]);
            offset += 4 + value.Length;
        }

        return buffer;
    }

    private static Dictionary<string, byte[]> ParseEntries(ReadOnlySpan<byte> data)
    {
        var entries = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        try
        {
            if (data.Length < 4)
            {
                throw Damaged();
            }

            int count = BinaryPrimitives.ReadInt32BigEndian(data);
            int offset = 4;
            for (int i = 0; i < count; i++)
            {
                if (offset + 2 > data.Length)
                {
                    throw Damaged();
                }

                int nameLength = BinaryPrimitives.ReadUInt16BigEndian(data[offset..]);
                offset += 2;
                if (offset + nameLength + 4 > data.Length)
                {
                    throw Damaged();
                }

                string name = Encodings.DecodeUtf8(data.Slice(offset, nameLength));
                offset += nameLength;
                int valueLength = BinaryPrimitives.ReadInt32BigEndian(data[offset..]);
                offset += 4;
                if (valueLength < 0 || offset + valueLength > data.Length)
                {
                    throw Damaged();
                }

                byte[] value = GC.AllocateUninitializedArray<byte>(valueLength, pinned: true);
                data.Slice(offset, valueLength).CopyTo(value);
                offset += valueLength;
                entries[name] = value;
            }

            return entries;
        }
        catch
        {
            Wipe(entries);
            throw;
        }
    }

    private static CaltropException Damaged() => Errors.InvalidFormat("the vault's contents are damaged.");

    private static void ValidateName(string name)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);
        if (name.Length > MaxNameLength)
        {
            throw new ArgumentException($"A secret's name can be at most {MaxNameLength} characters.", nameof(name));
        }
    }
}
