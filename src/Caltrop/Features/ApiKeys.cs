using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using CaltropSecurity.Internal;

namespace CaltropSecurity;

public static partial class Caltrop
{
    /// <summary>
    /// API keys for your own API: generate them, store only their hash, and check incoming keys.
    /// </summary>
    /// <example>
    /// <code>
    /// // Issue a key: show it to the customer once, store only the hash.
    /// string apiKey = Caltrop.ApiKeys.Generate("acme_live");   // acme_live_4fT9...
    /// customer.ApiKeyHash = Caltrop.ApiKeys.Hash(apiKey);
    ///
    /// // On each request: cheap format check first, then look up by hash.
    /// if (!Caltrop.ApiKeys.IsWellFormed(header, "acme_live")) return Unauthorized();
    /// var customer = db.Customers.SingleOrDefault(c => c.ApiKeyHash == Caltrop.ApiKeys.Hash(header));
    /// </code>
    /// </example>
    /// <remarks>
    /// Keys look like <c>prefix_</c> followed by 32 random letters and digits (about 190 bits) and a 6-character
    /// checksum. The checksum lets <see cref="IsWellFormed(string?, string?)"/> reject typos and junk without a
    /// database lookup, and helps secret scanners spot leaked keys. Because the keys are long and random, a fast
    /// SHA-256 hash is safe for storage, and you can index and look up by it.
    /// </remarks>
    public static class ApiKeys
    {
        private const int RandomLength = 32;
        private const int ChecksumLength = 6;
        private const int BodyLength = RandomLength + ChecksumLength;
        private const int MaxPrefixLength = 32;

        /// <summary>Creates a new API key with the given prefix.</summary>
        /// <param name="prefix">
        /// A short name that identifies your keys, such as <c>"acme"</c> or <c>"acme_live"</c>: letters, digits and
        /// underscores, starting with a letter, at most 32 characters.
        /// </param>
        /// <returns>The key, for example <c>acme_live_4fT9...</c>. Show it to its owner once; store <see cref="Hash(string)"/> instead.</returns>
        public static string Generate(string prefix)
        {
            ValidatePrefix(prefix);
            string random = RandomNumberGenerator.GetString(Base62.Alphabet, RandomLength);
            return $"{prefix}_{random}{Checksum(prefix, random)}";
        }

        /// <summary>
        /// Checks that a value has the shape of a key made by <see cref="Generate(string)"/>, including its checksum.
        /// It does not tell you whether the key exists; look up its <see cref="Hash(string)"/> for that.
        /// </summary>
        /// <param name="apiKey">The key from the request. <see langword="null"/> returns <see langword="false"/>.</param>
        /// <param name="prefix">If given, the key must have exactly this prefix.</param>
        /// <returns><see langword="true"/> if the key is well formed.</returns>
        public static bool IsWellFormed([NotNullWhen(true)] string? apiKey, string? prefix = null)
        {
            if (string.IsNullOrEmpty(apiKey))
            {
                return false;
            }

            int split = apiKey.LastIndexOf('_');
            if (split <= 0 || apiKey.Length - split - 1 != BodyLength)
            {
                return false;
            }

            string keyPrefix = apiKey[..split];
            ReadOnlySpan<char> body = apiKey.AsSpan(split + 1);
            if (!IsValidPrefix(keyPrefix) || (prefix is not null && !string.Equals(keyPrefix, prefix, StringComparison.Ordinal)) || !Base62.IsBase62(body))
            {
                return false;
            }

            string random = body[..RandomLength].ToString();
            return body[RandomLength..].SequenceEqual(Checksum(keyPrefix, random));
        }

        /// <summary>Hashes an API key for storage and lookup (SHA-256, lowercase hex).</summary>
        /// <param name="apiKey">The key.</param>
        /// <returns>The hash. The same key always gives the same hash, so you can index it.</returns>
        public static string Hash(string apiKey)
        {
            ArgumentException.ThrowIfNullOrEmpty(apiKey);
            return Convert.ToHexStringLower(SHA256.HashData(Encodings.Utf8(apiKey, nameof(apiKey))));
        }

        /// <summary>Checks a key against a stored hash in constant time.</summary>
        /// <param name="apiKey">The key from the request. <see langword="null"/> returns <see langword="false"/>.</param>
        /// <param name="storedHash">The hash stored when the key was issued.</param>
        /// <returns><see langword="true"/> if the key matches the hash.</returns>
        /// <exception cref="ArgumentException"><paramref name="storedHash"/> is not a hash made by <see cref="Hash(string)"/>.</exception>
        public static bool Verify([NotNullWhen(true)] string? apiKey, string storedHash)
        {
            ArgumentNullException.ThrowIfNull(storedHash);
            if (storedHash.Length != 64 || !Encodings.IsHex(storedHash))
            {
                throw new ArgumentException("This is not a hash made by Caltrop.ApiKeys.Hash.", nameof(storedHash));
            }

            if (string.IsNullOrEmpty(apiKey))
            {
                return false;
            }

            byte[] expected = Convert.FromHexString(storedHash);
            byte[] actual = SHA256.HashData(Encodings.Utf8(apiKey, nameof(apiKey)));
            return CryptographicOperations.FixedTimeEquals(actual, expected);
        }

        private static string Checksum(string prefix, string random)
        {
            Span<byte> digest = stackalloc byte[32];
            SHA256.HashData(Encodings.Utf8($"{prefix}_{random}", nameof(prefix)), digest);
            return Base62.EncodeUInt32(BinaryPrimitives.ReadUInt32BigEndian(digest));
        }

        private static void ValidatePrefix(string prefix)
        {
            ArgumentNullException.ThrowIfNull(prefix);
            if (!IsValidPrefix(prefix))
            {
                throw new ArgumentException(
                    "The prefix must be 1 to 32 letters, digits or underscores, start with a letter and not end with an underscore, for example \"acme\" or \"acme_live\".",
                    nameof(prefix));
            }
        }

        private static bool IsValidPrefix(string prefix)
        {
            if (prefix.Length is 0 or > MaxPrefixLength || !char.IsAsciiLetter(prefix[0]) || prefix[^1] == '_')
            {
                return false;
            }

            foreach (char c in prefix)
            {
                if (!char.IsAsciiLetterOrDigit(c) && c != '_')
                {
                    return false;
                }
            }

            return true;
        }
    }
}
