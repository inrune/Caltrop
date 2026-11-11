using System.Buffers;
using System.Buffers.Text;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using CaltropSecurity.Internal;

namespace CaltropSecurity;

public static partial class Caltrop
{
    /// <summary>
    /// Cryptographically secure random values: bytes, numbers, strings, tokens and passwords. Unlike
    /// <see cref="System.Random"/>, these cannot be predicted, so they are safe for secrets.
    /// </summary>
    public static class Random
    {
        private const string Upper = "ABCDEFGHJKLMNPQRSTUVWXYZ";
        private const string Lower = "abcdefghijkmnopqrstuvwxyz";
        private const string Digits = "23456789";
        private const string Symbols = "!@#$%^&*-_=+?";
        private const string PasswordAlphabet = Upper + Lower + Digits + Symbols;

        private static readonly SearchValues<char> s_upper = SearchValues.Create(Upper);
        private static readonly SearchValues<char> s_lower = SearchValues.Create(Lower);
        private static readonly SearchValues<char> s_digits = SearchValues.Create(Digits);
        private static readonly SearchValues<char> s_symbols = SearchValues.Create(Symbols);

        /// <summary>Returns <paramref name="count"/> random bytes.</summary>
        /// <param name="count">How many bytes.</param>
        /// <returns>The bytes.</returns>
        public static byte[] Bytes(int count)
        {
            ArgumentOutOfRangeException.ThrowIfNegative(count);
            return RandomNumberGenerator.GetBytes(count);
        }

        /// <summary>Returns a random number from 0 up to, but not including, <paramref name="maxExclusive"/>, with no bias.</summary>
        /// <param name="maxExclusive">The upper bound (exclusive). Must be positive.</param>
        /// <returns>The number.</returns>
        public static int Number(int maxExclusive) => RandomNumberGenerator.GetInt32(maxExclusive);

        /// <summary>Returns a random number from <paramref name="minInclusive"/> up to, but not including, <paramref name="maxExclusive"/>, with no bias.</summary>
        /// <param name="minInclusive">The lower bound (inclusive).</param>
        /// <param name="maxExclusive">The upper bound (exclusive).</param>
        /// <returns>The number.</returns>
        public static int Number(int minInclusive, int maxExclusive) => RandomNumberGenerator.GetInt32(minInclusive, maxExclusive);

        /// <summary>Returns a random string of letters and digits (A-Z, a-z, 0-9), about 5.95 bits per character.</summary>
        /// <param name="length">How many characters.</param>
        /// <returns>The string.</returns>
        [SuppressMessage("Naming", "CA1720:Identifier contains type name", Justification = "Caltrop.Random.String(n) is the name users look for.")]
        public static string String(int length)
        {
            ArgumentOutOfRangeException.ThrowIfNegative(length);
            return RandomNumberGenerator.GetString(Base62.Alphabet, length);
        }

        /// <summary>Returns a random string using only characters from <paramref name="alphabet"/>, each equally likely.</summary>
        /// <param name="length">How many characters.</param>
        /// <param name="alphabet">The characters to choose from, for example <c>"0123456789"</c>. No duplicates.</param>
        /// <returns>The string.</returns>
        [SuppressMessage("Naming", "CA1720:Identifier contains type name", Justification = "Caltrop.Random.String(n) is the name users look for.")]
        public static string String(int length, string alphabet)
        {
            ArgumentOutOfRangeException.ThrowIfNegative(length);
            ArgumentNullException.ThrowIfNull(alphabet);
            if (alphabet.Length < 2)
            {
                throw new ArgumentException("The alphabet needs at least 2 characters.", nameof(alphabet));
            }

            if (new HashSet<char>(alphabet).Count != alphabet.Length)
            {
                throw new ArgumentException("The alphabet contains duplicate characters, which would make some characters more likely than others.", nameof(alphabet));
            }

            return RandomNumberGenerator.GetString(alphabet, length);
        }

        /// <summary>
        /// Returns a random URL-safe token for session ids, CSRF tokens, reset links and similar.
        /// The default of 32 bytes gives 256 bits, a 43-character string.
        /// </summary>
        /// <param name="byteCount">How many random bytes to use; at least 16.</param>
        /// <returns>The token (Base64Url, no padding).</returns>
        public static string Token(int byteCount = 32)
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(byteCount, 16);
            ArgumentOutOfRangeException.ThrowIfGreaterThan(byteCount, 1024);
            return Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(byteCount));
        }

        /// <summary>
        /// Returns a strong random password containing upper and lower case letters, digits and symbols. Characters
        /// that are easy to confuse (I, l, 1, O, 0) are left out.
        /// </summary>
        /// <param name="length">How many characters, 8 to 1024. The default of 20 gives about 120 bits.</param>
        /// <returns>The password.</returns>
        public static string Password(int length = 20)
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(length, 8);
            ArgumentOutOfRangeException.ThrowIfGreaterThan(length, 1024);
            while (true)
            {
                // Redraw until every kind of character appears: uniform over all passwords that have them all.
                string candidate = RandomNumberGenerator.GetString(PasswordAlphabet, length);
                ReadOnlySpan<char> span = candidate;
                if (span.ContainsAny(s_upper) && span.ContainsAny(s_lower) && span.ContainsAny(s_digits) && span.ContainsAny(s_symbols))
                {
                    return candidate;
                }
            }
        }
    }
}
