using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using CaltropSecurity.Internal;

namespace CaltropSecurity;

public static partial class Caltrop
{
    /// <summary>
    /// Two-factor authentication with one-time codes from authenticator apps (Google Authenticator, Microsoft
    /// Authenticator, 1Password, Authy and others), plus single-use recovery codes.
    /// </summary>
    /// <example>
    /// <code>
    /// // Setup: store the secret with the user (encrypted, e.g. Caltrop.Encrypt(secret, key)), show the URI as a QR code.
    /// string secret = Caltrop.TwoFactor.CreateSecret();
    /// string uri    = Caltrop.TwoFactor.GetSetupUri(secret, user.Email, "My App");
    ///
    /// // Login
    /// bool ok = Caltrop.TwoFactor.Verify(secret, codeTheUserTyped);
    /// </code>
    /// </example>
    /// <remarks>
    /// Time-based one-time passwords as in RFC 6238: HMAC-SHA1, 6 digits, 30-second steps, accepting one step
    /// either side of the current time to allow for clock drift. HMAC-SHA1 is what authenticator apps support; it
    /// remains secure for this use.
    /// </remarks>
    public static class TwoFactor
    {
        private const int Digits = 6;
        private const int PeriodSeconds = 30;
        private const int AllowedDriftSteps = 1;
        private const int SecretSize = 20;
        private const int MinSecretSize = 10;
        private const int RecoveryCodeLength = 16;
        private const string RecoveryAlphabet = "23456789ABCDEFGHJKMNPQRSTUVWXYZ";

        /// <summary>Creates a new random secret (160 bits, Base32, 32 characters) for a user's authenticator app.</summary>
        /// <returns>The secret. Store it with the user, ideally encrypted. Anyone who has it can generate valid codes.</returns>
        public static string CreateSecret() => Base32.Encode(RandomNumberGenerator.GetBytes(SecretSize));

        /// <summary>
        /// Builds the <c>otpauth://</c> link that authenticator apps read from a QR code. Show it as a QR code (with
        /// any QR library) on your 2FA setup page, along with the secret for manual entry.
        /// </summary>
        /// <param name="secret">The secret from <see cref="CreateSecret"/>.</param>
        /// <param name="accountName">What the app shows for this account, usually the user's email address.</param>
        /// <param name="issuer">Your app or company name, shown above the code.</param>
        /// <returns>The setup link.</returns>
        public static string GetSetupUri(string secret, string accountName, string issuer)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(accountName);
            ArgumentException.ThrowIfNullOrWhiteSpace(issuer);
            if (issuer.Contains(':', StringComparison.Ordinal))
            {
                throw new ArgumentException("The issuer must not contain a colon (:).", nameof(issuer));
            }

            if (accountName.Contains(':', StringComparison.Ordinal))
            {
                throw new ArgumentException("The account name must not contain a colon (:).", nameof(accountName));
            }

            byte[] key = DecodeSecret(secret);
            string normalizedSecret = Base32.Encode(key);
            CryptographicOperations.ZeroMemory(key);
            string label = Uri.EscapeDataString(issuer) + ":" + Uri.EscapeDataString(accountName);
            return string.Create(
                CultureInfo.InvariantCulture,
                $"otpauth://totp/{label}?secret={normalizedSecret}&issuer={Uri.EscapeDataString(issuer)}&algorithm=SHA1&digits={Digits}&period={PeriodSeconds}");
        }

        /// <summary>Returns the code an authenticator app shows right now. Useful in tests and admin tools.</summary>
        /// <param name="secret">The secret.</param>
        /// <returns>A 6-digit code.</returns>
        public static string GetCode(string secret) => GetCode(secret, DateTimeOffset.UtcNow);

        /// <summary>Returns the code an authenticator app shows at <paramref name="time"/>.</summary>
        /// <param name="secret">The secret.</param>
        /// <param name="time">The moment to compute the code for.</param>
        /// <returns>A 6-digit code.</returns>
        public static string GetCode(string secret, DateTimeOffset time)
        {
            byte[] key = DecodeSecret(secret);
            try
            {
                return FormatCode(Hotp(key, TimeStep(time), Digits), Digits);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(key);
            }
        }

        /// <summary>Checks a code typed by the user. Spaces and dashes are ignored.</summary>
        /// <param name="secret">The user's secret.</param>
        /// <param name="code">The code the user typed. <see langword="null"/> or badly formed codes return <see langword="false"/>.</param>
        /// <returns><see langword="true"/> if the code is valid now (within 30 seconds either side).</returns>
        /// <remarks>
        /// A code stays valid for its whole time window, so someone watching could reuse it. To block that, use the
        /// overload with <c>lastUsedStep</c>.
        /// </remarks>
        public static bool Verify(string secret, [NotNullWhen(true)] string? code) =>
            Verify(secret, code, DateTimeOffset.UtcNow, long.MinValue, out _);

        /// <summary>
        /// Checks a code and refuses any code from a time step that was already used, so each code works only once.
        /// Store <paramref name="usedStep"/> with the user after a successful check and pass it back next time.
        /// </summary>
        /// <param name="secret">The user's secret.</param>
        /// <param name="code">The code the user typed.</param>
        /// <param name="lastUsedStep">The <paramref name="usedStep"/> stored after the user's last successful check, or 0 if none.</param>
        /// <param name="usedStep">On success, the time step of the code. Store it for the next call.</param>
        /// <returns><see langword="true"/> if the code is valid and newer than <paramref name="lastUsedStep"/>.</returns>
        public static bool Verify(string secret, [NotNullWhen(true)] string? code, long lastUsedStep, out long usedStep) =>
            Verify(secret, code, DateTimeOffset.UtcNow, lastUsedStep, out usedStep);

        /// <summary>
        /// Creates single-use recovery codes such as <c>7KQ2-M9HC-DX4P-T8WN</c> that users keep in case they lose their
        /// device. Show them once, store only <see cref="HashRecoveryCode(string)"/> of each, and delete a hash once its code is used.
        /// </summary>
        /// <param name="count">How many codes to create (1 to 100).</param>
        /// <returns>The codes, each about 79 bits of randomness.</returns>
        public static string[] CreateRecoveryCodes(int count = 10)
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(count, 1);
            ArgumentOutOfRangeException.ThrowIfGreaterThan(count, 100);
            var codes = new string[count];
            for (int i = 0; i < count; i++)
            {
                string raw = RandomNumberGenerator.GetString(RecoveryAlphabet, RecoveryCodeLength);
                codes[i] = string.Join('-', raw[..4], raw[4..8], raw[8..12], raw[12..]);
            }

            return codes;
        }

        /// <summary>
        /// Hashes a recovery code for storage and lookup. Case, spaces and dashes are ignored, so what the user
        /// types matches what you stored.
        /// </summary>
        /// <param name="code">A code from <see cref="CreateRecoveryCodes(int)"/>, or what the user typed.</param>
        /// <returns>A SHA-256 hash as lowercase hex.</returns>
        public static string HashRecoveryCode(string code)
        {
            ArgumentNullException.ThrowIfNull(code);
            var normalized = new StringBuilder(code.Length);
            foreach (char c in code)
            {
                if (c is not (' ' or '-' or '\t'))
                {
                    normalized.Append(char.ToUpperInvariant(c));
                }
            }

            return Convert.ToHexStringLower(SHA256.HashData(Encodings.Utf8(normalized.ToString(), nameof(code))));
        }

        internal static bool Verify(string secret, string? code, DateTimeOffset now, long lastUsedStep, out long usedStep)
        {
            usedStep = 0;
            byte[] key = DecodeSecret(secret); // throws for a bad secret even when the code is bad
            try
            {
                if (!TryParseCode(code, out int value))
                {
                    return false;
                }

                long current = TimeStep(now);
                bool found = false;
                for (long step = current - AllowedDriftSteps; step <= current + AllowedDriftSteps; step++)
                {
                    // Every step is computed, so the time taken does not reveal which one matched.
                    bool match = Hotp(key, step, Digits) == value;
                    if (match && !found && step > lastUsedStep)
                    {
                        found = true;
                        usedStep = step;
                    }
                }

                return found;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(key);
            }
        }

        /// <summary>HOTP as defined in RFC 4226.</summary>
        [SuppressMessage("Security", "CA5350:Do Not Use Weak Cryptographic Algorithms", Justification = "RFC 6238 TOTP uses HMAC-SHA1, the only algorithm authenticator apps reliably support. HMAC-SHA1 is still a secure PRF; SHA-1 collisions do not affect it.")]
        internal static int Hotp(ReadOnlySpan<byte> key, long counter, int digits)
        {
            Span<byte> message = stackalloc byte[8];
            BinaryPrimitives.WriteInt64BigEndian(message, counter);
            Span<byte> mac = stackalloc byte[HMACSHA1.HashSizeInBytes];
            HMACSHA1.HashData(key, message, mac);
            int offset = mac[^1] & 0x0F;
            int binary = ((mac[offset] & 0x7F) << 24) | (mac[offset + 1] << 16) | (mac[offset + 2] << 8) | mac[offset + 3];
            int modulus = 1;
            for (int i = 0; i < digits; i++)
            {
                modulus *= 10;
            }

            return binary % modulus;
        }

        internal static string FormatCode(int code, int digits) => code.ToString(CultureInfo.InvariantCulture).PadLeft(digits, '0');

        private static long TimeStep(DateTimeOffset time) => Math.DivRem(time.ToUnixTimeSeconds(), PeriodSeconds, out long remainder) - (remainder < 0 ? 1 : 0);

        private static byte[] DecodeSecret(string secret)
        {
            ArgumentNullException.ThrowIfNull(secret);
            if (!Base32.TryDecode(secret, out byte[] key) || key.Length < MinSecretSize)
            {
                CryptographicOperations.ZeroMemory(key);
                throw new ArgumentException("The secret is not a valid two-factor secret. Use one made by Caltrop.TwoFactor.CreateSecret().", nameof(secret));
            }

            return key;
        }

        private static bool TryParseCode(string? code, out int value)
        {
            value = 0;
            if (code is null)
            {
                return false;
            }

            int digits = 0;
            foreach (char c in code)
            {
                if (c is ' ' or '-')
                {
                    continue;
                }

                if (c is < '0' or > '9' || ++digits > Digits)
                {
                    return false;
                }

                value = (value * 10) + (c - '0');
            }

            return digits == Digits;
        }
    }
}
