using System.Buffers.Binary;
using System.Security.Cryptography;
using CaltropSecurity.Internal;

public static partial class Caltrop
{
    /// <summary>
    /// Tamper checks: seal data, files or whole folders now, and check later that nothing changed. A failed check
    /// sets off a <see cref="CaltropAlarmKind.Tampering"/> alarm (see <see cref="Traps"/>).
    /// <see cref="CheckCaltrop"/> checks Caltrop.dll itself.
    /// </summary>
    /// <example>
    /// <code>
    /// // When you save or ship a file:
    /// string seal = Caltrop.Tamper.SealFile("settings.json");      // store the seal somewhere else
    ///
    /// // Later, before trusting it:
    /// if (!Caltrop.Tamper.CheckFile("settings.json", seal))
    ///     throw new Exception("settings.json was changed!");
    ///
    /// // When your app starts:
    /// if (Caltrop.Tamper.CheckCaltrop() == CaltropIntegrity.Changed) { /* the alarm has gone off */ }
    /// </code>
    /// </example>
    /// <remarks>
    /// A seal is a short <c>cts_...</c> string: an HMAC-SHA256 of the content, made with your key, so nobody without
    /// the key can make a seal that matches changed content. The seal is not secret, but keep it apart from what it
    /// protects (in your database or code, not next to the file), or an attacker could delete both.
    /// </remarks>
    public static class Tamper
    {
        private const string SealPrefix = "cts_";
        private const byte ContentSeal = 0x01;
        private const byte FolderSeal = 0x02;
        private const int MacSize = 32;
        private const int PayloadSize = 1 + Format.KeyIdSize + MacSize;

        /// <summary>Seals bytes.</summary>
        /// <param name="data">The data to protect.</param>
        /// <param name="key">The key to seal with. Defaults to the default key.</param>
        /// <returns>The seal, a <c>cts_...</c> string.</returns>
        public static string Seal(byte[] data, CaltropKey? key = null)
        {
            ArgumentNullException.ThrowIfNull(data);
            key ??= DefaultKeys.Primary;
            using IncrementalHash mac = StartMac(key, ContentSeal);
            mac.AppendData(data);
            return Finish(mac, key, ContentSeal);
        }

        /// <summary>Seals text (as UTF-8).</summary>
        /// <param name="text">The text to protect.</param>
        /// <param name="key">The key to seal with. Defaults to the default key.</param>
        /// <returns>The seal, a <c>cts_...</c> string.</returns>
        public static string Seal(string text, CaltropKey? key = null)
        {
            ArgumentNullException.ThrowIfNull(text);
            return Seal(Encodings.Utf8(text, nameof(text)), key);
        }

        /// <summary>Checks bytes against their seal. A mismatch sets off the alarm.</summary>
        /// <param name="data">The data as it is now.</param>
        /// <param name="seal">The seal made by <see cref="Seal(byte[], CaltropKey?)"/>.</param>
        /// <param name="key">The key it was sealed with. Defaults to the default keys.</param>
        /// <returns><see langword="true"/> if the data is exactly as it was when sealed.</returns>
        public static bool Check(byte[] data, string? seal, CaltropKey? key = null)
        {
            ArgumentNullException.ThrowIfNull(data);
            if (!TryOpenSeal(seal, ContentSeal, key, "Data", subject: null, out CaltropKey? sealKey, out byte[] expected))
            {
                return false;
            }

            using IncrementalHash mac = StartMac(sealKey, ContentSeal);
            mac.AppendData(data);
            return Compare(mac, expected, "Data", "The data does not match its seal: it was changed.", subject: null);
        }

        /// <summary>Checks text against its seal. A mismatch sets off the alarm.</summary>
        /// <param name="text">The text as it is now.</param>
        /// <param name="seal">The seal made by <see cref="Seal(string, CaltropKey?)"/>.</param>
        /// <param name="key">The key it was sealed with. Defaults to the default keys.</param>
        /// <returns><see langword="true"/> if the text is exactly as it was when sealed.</returns>
        public static bool Check(string text, string? seal, CaltropKey? key = null)
        {
            ArgumentNullException.ThrowIfNull(text);
            return Check(Encodings.Utf8(text, nameof(text)), seal, key);
        }

        /// <summary>Seals a file's contents.</summary>
        /// <param name="path">The file.</param>
        /// <param name="key">The key to seal with. Defaults to the default key.</param>
        /// <returns>The seal, a <c>cts_...</c> string. Store it somewhere other than next to the file.</returns>
        public static string SealFile(string path, CaltropKey? key = null)
        {
            ArgumentException.ThrowIfNullOrEmpty(path);
            key ??= DefaultKeys.Primary;
            using IncrementalHash mac = StartMac(key, ContentSeal);
            AppendFile(mac, path);
            return Finish(mac, key, ContentSeal);
        }

        /// <summary>Checks a file against its seal. A changed or missing file sets off the alarm.</summary>
        /// <param name="path">The file.</param>
        /// <param name="seal">The seal made by <see cref="SealFile(string, CaltropKey?)"/>.</param>
        /// <param name="key">The key it was sealed with. Defaults to the default keys.</param>
        /// <returns><see langword="true"/> if the file is exactly as it was when sealed.</returns>
        public static bool CheckFile(string path, string? seal, CaltropKey? key = null)
        {
            ArgumentException.ThrowIfNullOrEmpty(path);
            if (!TryOpenSeal(seal, ContentSeal, key, "File", path, out CaltropKey? sealKey, out byte[] expected))
            {
                return false;
            }

            if (!File.Exists(path))
            {
                Tampering.Raise("File seal", $"The sealed file {path} is missing.", path);
                return false;
            }

            using IncrementalHash mac = StartMac(sealKey, ContentSeal);
            AppendFile(mac, path);
            return Compare(mac, expected, "File seal", $"The file {path} does not match its seal: it was changed.", path);
        }

        /// <summary>
        /// Seals a whole folder, including subfolders and hidden files: their names and contents. Adding, removing,
        /// renaming or changing any file breaks the seal.
        /// </summary>
        /// <param name="folder">The folder.</param>
        /// <param name="key">The key to seal with. Defaults to the default key.</param>
        /// <returns>The seal, a <c>cts_...</c> string. Store it outside the folder.</returns>
        public static string SealFolder(string folder, CaltropKey? key = null)
        {
            ArgumentException.ThrowIfNullOrEmpty(folder);
            key ??= DefaultKeys.Primary;
            using IncrementalHash mac = StartMac(key, FolderSeal);
            AppendFolder(mac, folder);
            return Finish(mac, key, FolderSeal);
        }

        /// <summary>Checks a folder against its seal. Any added, removed, renamed or changed file sets off the alarm.</summary>
        /// <param name="folder">The folder.</param>
        /// <param name="seal">The seal made by <see cref="SealFolder(string, CaltropKey?)"/>.</param>
        /// <param name="key">The key it was sealed with. Defaults to the default keys.</param>
        /// <returns><see langword="true"/> if every file is exactly as it was when sealed.</returns>
        public static bool CheckFolder(string folder, string? seal, CaltropKey? key = null)
        {
            ArgumentException.ThrowIfNullOrEmpty(folder);
            if (!TryOpenSeal(seal, FolderSeal, key, "Folder", folder, out CaltropKey? sealKey, out byte[] expected))
            {
                return false;
            }

            if (!Directory.Exists(folder))
            {
                Tampering.Raise("Folder seal", $"The sealed folder {folder} is missing.", folder);
                return false;
            }

            using IncrementalHash mac = StartMac(sealKey, FolderSeal);
            AppendFolder(mac, folder);
            return Compare(mac, expected, "Folder seal", $"The folder {folder} does not match its seal: a file was added, removed, renamed or changed.", folder);
        }

        /// <summary>
        /// Checks that Caltrop.dll is exactly the file its build produced. Every build seals the DLL; if anyone
        /// changes even one byte afterwards, this returns <see cref="CaltropIntegrity.Changed"/> and the alarm goes off.
        /// </summary>
        /// <returns>
        /// <see cref="CaltropIntegrity.Intact"/>, <see cref="CaltropIntegrity.Changed"/>, or
        /// <see cref="CaltropIntegrity.CannotCheck"/> when Caltrop is not loaded from a file (single-file or Native AOT apps).
        /// </returns>
        /// <remarks>
        /// This catches damaged files and casual tampering. A skilled attacker who can change files on the machine can
        /// also change this check, so it is one layer of defence, not a guarantee.
        /// </remarks>
        public static CaltropIntegrity CheckCaltrop()
        {
            CaltropIntegrity result = SelfSeal.Check(out string? path);
            if (result == CaltropIntegrity.Changed)
            {
                Tampering.Raise("Caltrop.dll check", $"Caltrop.dll has been changed since it was built ({path}).", path);
            }

            return result;
        }

        private static IncrementalHash StartMac(CaltropKey key, byte kind)
        {
            Span<byte> macKey = stackalloc byte[Format.KeySize];
            try
            {
                key.Derive(Labels.Tamper, [kind], macKey);
                return IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, macKey);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(macKey);
            }
        }

        private static string Finish(IncrementalHash mac, CaltropKey key, byte kind)
        {
            Span<byte> payload = stackalloc byte[PayloadSize];
            payload[0] = kind;
            key.IdBytes.CopyTo(payload[1..]);
            mac.GetHashAndReset(payload[(1 + Format.KeyIdSize)..]);
            Traps.ThrowIfLockedDownAfterUse();
            return KeyText.Encode(SealPrefix, payload);
        }

        private static bool TryOpenSeal(string? seal, byte kind, CaltropKey? key, string what, string? subject, out CaltropKey sealKey, out byte[] expected)
        {
            sealKey = null!;
            expected = [];
            CaltropKeyRing keys = key is null ? DefaultKeys : new CaltropKeyRing(key);
            if (seal is null || !KeyText.TryDecode(seal, SealPrefix, PayloadSize, out byte[] payload, out _) || payload[0] != kind)
            {
                Tampering.Raise($"{what} seal", $"The seal for {Describe(what, subject)} is damaged, or is not a Caltrop seal of the right kind.", subject);
                return false;
            }

            ReadOnlySpan<byte> keyId = payload.AsSpan(1, Format.KeyIdSize);
            foreach (CaltropKey candidate in keys)
            {
                if (candidate.Matches(keyId))
                {
                    sealKey = candidate;
                    expected = payload[(1 + Format.KeyIdSize)..];
                    return true;
                }
            }

            Tampering.Raise($"{what} seal", $"The seal for {Describe(what, subject)} was made with a different key (key id {Convert.ToHexStringLower(keyId)}).", subject);
            return false;
        }

        private static bool Compare(IncrementalHash mac, byte[] expected, string trap, string message, string? subject)
        {
            byte[] actual = mac.GetHashAndReset();
            Traps.ThrowIfLockedDownAfterUse();
            if (CryptographicOperations.FixedTimeEquals(actual, expected))
            {
                return true;
            }

            Tampering.Raise(trap, message, subject);
            return false;
        }

        private static string Describe(string what, string? subject) => subject is null ? what.ToLowerInvariant() : $"{what.ToLowerInvariant()} {subject}";

        private static void AppendFile(IncrementalHash mac, string path)
        {
            using FileStream stream = File.OpenRead(path);
            byte[] buffer = new byte[64 * 1024];
            int read;
            while ((read = stream.Read(buffer)) > 0)
            {
                mac.AppendData(buffer, 0, read);
            }
        }

        /// <summary>Feeds the MAC: for each file in name order, its relative path (length-prefixed) and the SHA-256 of its contents.</summary>
        private static void AppendFolder(IncrementalHash mac, string folder)
        {
            string root = Path.GetFullPath(folder);
            var options = new EnumerationOptions
            {
                RecurseSubdirectories = true,
                AttributesToSkip = 0, // include hidden and system files: an attacker could hide a file
                IgnoreInaccessible = false,
                MaxRecursionDepth = 64,
            };

            string[] relative = [.. Directory.EnumerateFiles(root, "*", options).Select(file => Path.GetRelativePath(root, file).Replace('\\', '/'))];
            Array.Sort(relative, StringComparer.Ordinal);

            Span<byte> length = stackalloc byte[4];
            foreach (string name in relative)
            {
                byte[] nameBytes = Encodings.Utf8(name, nameof(folder));
                BinaryPrimitives.WriteInt32BigEndian(length, nameBytes.Length);
                mac.AppendData(length);
                mac.AppendData(nameBytes);
                using FileStream stream = File.OpenRead(Path.Combine(root, name));
                mac.AppendData(SHA256.HashData(stream));
            }
        }
    }
}

/// <summary>The result of <see cref="Caltrop.Tamper.CheckCaltrop"/>.</summary>
public enum CaltropIntegrity
{
    /// <summary>Caltrop.dll is exactly the file its build produced.</summary>
    Intact,

    /// <summary>Caltrop.dll was changed after it was built. The alarm has gone off.</summary>
    Changed,

    /// <summary>Caltrop is not loaded from a separate file (for example a single-file or Native AOT app), so there is nothing to check.</summary>
    CannotCheck,
}
