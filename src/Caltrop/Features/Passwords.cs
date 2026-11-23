using System.Globalization;
using System.Security.Cryptography;
using CaltropSecurity.Internal;

public static partial class Caltrop
{
    /// <summary>
    /// Password hashing for user accounts. Never store passwords; store <see cref="Hash(string)"/> and check logins
    /// with <see cref="Verify(string, string)"/>.
    /// </summary>
    /// <example>
    /// <code>
    /// // Sign-up
    /// user.PasswordHash = Caltrop.Passwords.Hash(password);
    ///
    /// // Login
    /// if (Caltrop.Passwords.Verify(password, user.PasswordHash))
    /// {
    ///     if (Caltrop.Passwords.NeedsRehash(user.PasswordHash))
    ///         user.PasswordHash = Caltrop.Passwords.Hash(password);   // upgrade old hashes as users log in
    ///     // signed in
    /// }
    /// </code>
    /// </example>
    /// <remarks>
    /// PBKDF2-HMAC-SHA256 with 600,000 iterations and a random 16-byte salt (the OWASP recommendation), stored in
    /// the standard PHC string format: <c>$pbkdf2-sha256$i=600000$&lt;salt&gt;$&lt;hash&gt;</c>. Hashing takes a
    /// fraction of a second on purpose, to make stolen hashes slow to crack. Passwords are Unicode-normalized (NFC)
    /// first, so the same password typed on different devices always matches.
    /// </remarks>
    public static partial class Passwords
    {
        private const string Algorithm = "pbkdf2-sha256";
        private const int HashSize = 32;

        /// <summary>Hashes a password for storage. Every call uses a new random salt, so the same password gives a different result each time.</summary>
        /// <param name="password">The password. Must not be empty.</param>
        /// <returns>A string of about 90 characters to store with the user record.</returns>
        public static string Hash(string password) => Hash(password, PasswordKdf.DefaultIterations);

        /// <summary>Checks a password against a hash made by <see cref="Hash(string)"/>.</summary>
        /// <param name="password">The password the user typed.</param>
        /// <param name="hash">The stored hash.</param>
        /// <returns><see langword="true"/> if the password is correct.</returns>
        /// <exception cref="CaltropException">
        /// <paramref name="hash"/> is not a Caltrop password hash (<see cref="CaltropErrorCode.InvalidFormat"/>).
        /// This usually means the arguments were swapped, or the wrong column was read.
        /// </exception>
        public static bool Verify(string password, string hash)
        {
            ArgumentNullException.ThrowIfNull(password);
            ArgumentNullException.ThrowIfNull(hash);
            if (!TryParse(hash, out int iterations, out byte[] salt, out byte[] expected))
            {
                throw new CaltropException(
                    CaltropErrorCode.InvalidFormat,
                    "The stored value is not a Caltrop password hash. Check that the arguments are in the right order: Verify(password, hash).");
            }

            // A decoy account still costs a full hash, so its timing gives nothing away.
            bool decoy = Decoys.IsDecoySalt(salt);
            byte[] actual = new byte[expected.Length];
            try
            {
                PasswordKdf.Derive(password, salt, iterations, actual);
                if (decoy)
                {
                    Decoys.RaisePasswordAlarm();
                    Traps.ThrowIfLockedDown();
                    return false;
                }

                return CryptographicOperations.FixedTimeEquals(actual, expected);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(actual);
            }
        }

        /// <summary>
        /// Returns <see langword="true"/> if a hash was made with weaker settings than the current ones. After a
        /// successful <see cref="Verify(string, string)"/>, hash the password again and store the new hash.
        /// </summary>
        /// <param name="hash">The stored hash.</param>
        /// <returns><see langword="true"/> if the hash should be replaced.</returns>
        public static bool NeedsRehash(string hash)
        {
            ArgumentNullException.ThrowIfNull(hash);
            return !TryParse(hash, out int iterations, out _, out _)
                || iterations < PasswordKdf.DefaultIterations;
        }

        /// <summary>Hashes with a custom iteration count (tests use a low count to run quickly).</summary>
        internal static string Hash(string password, int iterations)
        {
            PasswordKdf.ValidateNewPassword(password, nameof(password));
            ArgumentOutOfRangeException.ThrowIfLessThan(iterations, 1);
            Span<byte> salt = stackalloc byte[PasswordKdf.SaltSize];
            RandomNumberGenerator.Fill(salt);
            Span<byte> hash = stackalloc byte[HashSize];
            try
            {
                PasswordKdf.Derive(password, salt, iterations, hash);
                return Format(iterations, salt, hash);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(hash);
            }
        }

        internal static string Format(int iterations, ReadOnlySpan<byte> salt, ReadOnlySpan<byte> hash) =>
            string.Create(
                CultureInfo.InvariantCulture,
                $"${Algorithm}$i={iterations}${Encodings.ToBase64NoPadding(salt)}${Encodings.ToBase64NoPadding(hash)}");

        internal static bool TryParse(string text, out int iterations, out byte[] salt, out byte[] hash)
        {
            iterations = 0;
            salt = [];
            hash = [];

            // "", "pbkdf2-sha256", "i=600000", salt, hash
            string[] parts = text.Trim().Split('$');
            if (parts.Length != 5 || parts[0].Length != 0 || !string.Equals(parts[1], Algorithm, StringComparison.Ordinal))
            {
                return false;
            }

            ReadOnlySpan<char> parameters = parts[2];
            if (!parameters.StartsWith("i=", StringComparison.Ordinal)
                || parameters[2..].StartsWith('0') // one spelling per number
                || parameters[2..].ContainsAnyExceptInRange('0', '9') // .NET would also skip a trailing \0
                || !int.TryParse(parameters[2..], NumberStyles.None, CultureInfo.InvariantCulture, out iterations)
                || iterations is < 1 or > PasswordKdf.MaximumIterations)
            {
                return false;
            }

            // Other tools pick other salt sizes, but a PBKDF2-SHA256 hash is always 32 bytes: a shorter one would be
            // a cut-down copy that still matched the password.
            return Encodings.TryFromBase64(parts[3], out salt, allowPadding: false) // the PHC format has none
                && salt.Length is >= 8 and <= 64
                && Encodings.TryFromBase64(parts[4], out hash, allowPadding: false)
                && hash.Length == HashSize;
        }
    }
}
