using System.Security.Cryptography;
using CaltropSecurity.Internal;

namespace CaltropSecurity;

public static partial class Caltrop
{
    /// <summary>
    /// Hashes and keyed hashes. Results are lowercase hex strings, ready to store or compare.
    /// </summary>
    /// <remarks>
    /// A plain hash (SHA-256) is for checksums and fingerprints. Do not use it for passwords; use
    /// <see cref="Passwords"/>. To look up encrypted values, use <see cref="BlindIndex(string, CaltropKey, string?)"/>.
    /// </remarks>
    public static class Hashing
    {
        /// <summary>SHA-256 of the UTF-8 bytes of <paramref name="text"/>.</summary>
        /// <param name="text">The text to hash.</param>
        /// <returns>64 lowercase hex characters.</returns>
        public static string Sha256(string text)
        {
            ArgumentNullException.ThrowIfNull(text);
            return Convert.ToHexStringLower(SHA256.HashData(Encodings.Utf8(text, nameof(text))));
        }

        /// <summary>SHA-256 of <paramref name="data"/>.</summary>
        /// <param name="data">The data to hash.</param>
        /// <returns>64 lowercase hex characters.</returns>
        public static string Sha256(byte[] data)
        {
            ArgumentNullException.ThrowIfNull(data);
            return Convert.ToHexStringLower(SHA256.HashData(data));
        }

        /// <summary>SHA-256 of everything read from <paramref name="stream"/>.</summary>
        /// <param name="stream">The stream, read to the end. It is not closed.</param>
        /// <returns>64 lowercase hex characters.</returns>
        public static string Sha256(Stream stream)
        {
            ArgumentNullException.ThrowIfNull(stream);
            return Convert.ToHexStringLower(SHA256.HashData(stream));
        }

        /// <summary>SHA-256 of a file, as used for download checksums (matches <c>sha256sum</c>).</summary>
        /// <param name="path">The file.</param>
        /// <returns>64 lowercase hex characters.</returns>
        public static string Sha256File(string path)
        {
            ArgumentException.ThrowIfNullOrEmpty(path);
            using FileStream stream = File.OpenRead(path);
            return Sha256(stream);
        }

        /// <summary>SHA-512 of the UTF-8 bytes of <paramref name="text"/>.</summary>
        /// <param name="text">The text to hash.</param>
        /// <returns>128 lowercase hex characters.</returns>
        public static string Sha512(string text)
        {
            ArgumentNullException.ThrowIfNull(text);
            return Convert.ToHexStringLower(SHA512.HashData(Encodings.Utf8(text, nameof(text))));
        }

        /// <summary>SHA-512 of <paramref name="data"/>.</summary>
        /// <param name="data">The data to hash.</param>
        /// <returns>128 lowercase hex characters.</returns>
        public static string Sha512(byte[] data)
        {
            ArgumentNullException.ThrowIfNull(data);
            return Convert.ToHexStringLower(SHA512.HashData(data));
        }

        /// <summary>HMAC-SHA256 of a message with a secret, both as UTF-8 text.</summary>
        /// <param name="message">The message.</param>
        /// <param name="secret">The secret.</param>
        /// <returns>64 lowercase hex characters.</returns>
        public static string HmacSha256(string message, string secret)
        {
            ArgumentNullException.ThrowIfNull(message);
            ArgumentException.ThrowIfNullOrEmpty(secret);
            return Convert.ToHexStringLower(HMACSHA256.HashData(Encodings.Utf8(secret, nameof(secret)), Encodings.Utf8(message, nameof(message))));
        }

        /// <summary>HMAC-SHA256 of a message with a key.</summary>
        /// <param name="message">The message.</param>
        /// <param name="key">The key.</param>
        /// <returns>64 lowercase hex characters.</returns>
        public static string HmacSha256(byte[] message, byte[] key)
        {
            ArgumentNullException.ThrowIfNull(message);
            ArgumentNullException.ThrowIfNull(key);
            return Convert.ToHexStringLower(HMACSHA256.HashData(key, message));
        }

        /// <summary>
        /// A "blind index": a keyed hash that lets you search encrypted data. Store it next to the encrypted value,
        /// then find rows with <c>WHERE email_index = BlindIndex(input, key)</c> without decrypting anything.
        /// </summary>
        /// <param name="value">
        /// The value to index. Normalize it first if lookups should ignore case or spaces, for example
        /// <c>email.Trim().ToLowerInvariant()</c>.
        /// </param>
        /// <param name="key">The secret key. Without it, nobody can compute or reverse the index.</param>
        /// <param name="purpose">
        /// Optional label such as <c>"users.email"</c>, so the same value gives different indexes in different
        /// columns. Use the same purpose to look up as to store.
        /// </param>
        /// <returns>64 lowercase hex characters. The same inputs always give the same result.</returns>
        /// <remarks>Equal values have equal indexes, so anyone who can read the column can see which rows share a value.</remarks>
        /// <example>
        /// <code>
        /// user.EmailEncrypted = Caltrop.Encrypt(email, key);
        /// user.EmailIndex     = Caltrop.Hashing.BlindIndex(email.ToLowerInvariant(), key, "users.email");
        /// </code>
        /// </example>
        public static string BlindIndex(string value, CaltropKey key, string? purpose = null)
        {
            ArgumentNullException.ThrowIfNull(value);
            ArgumentNullException.ThrowIfNull(key);
            Span<byte> indexKey = stackalloc byte[Format.KeySize];
            try
            {
                key.Derive(Labels.BlindIndex, Encodings.Utf8(purpose, nameof(purpose)), indexKey);
                return Convert.ToHexStringLower(HMACSHA256.HashData(indexKey, Encodings.Utf8(value, nameof(value))));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(indexKey);
            }
        }
    }
}
