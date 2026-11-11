using System.Buffers.Text;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Security.Cryptography;
using CaltropSecurity.Internal;

namespace CaltropSecurity;

public static partial class Caltrop
{
    /// <summary>
    /// Signs and verifies webhook payloads with a shared secret (HMAC-SHA256), for webhooks you send or receive.
    /// </summary>
    /// <example>
    /// <code>
    /// // Receiving (GitHub-style "X-Hub-Signature-256: sha256=..." header). Verify the raw body bytes.
    /// if (!Caltrop.Webhooks.Verify(rawBody, request.Headers["X-Hub-Signature-256"], secret))
    ///     return Unauthorized();
    ///
    /// // Sending, with a timestamp that blocks replays: "t=1731234567,v1=5257a8..."
    /// string signature = Caltrop.Webhooks.SignWithTimestamp(body, secret);
    /// </code>
    /// </example>
    /// <remarks>Comparisons are constant-time. Always verify the exact bytes you received, before parsing them.</remarks>
    public static class Webhooks
    {
        private const string SignaturePrefix = "sha256=";
        private const int MacSize = 32;

        /// <summary>The default time window for <see cref="VerifyWithTimestamp(string, string?, string, TimeSpan?)"/>: 5 minutes.</summary>
        public static readonly TimeSpan DefaultTolerance = TimeSpan.FromMinutes(5);

        /// <summary>Creates a new random webhook secret (<c>whsec_</c> followed by 256 random bits).</summary>
        /// <returns>The secret. Share it with the other side over a secure channel.</returns>
        public static string CreateSecret() => "whsec_" + Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(32));

        /// <summary>Signs a payload. Returns <c>sha256=</c> followed by the HMAC-SHA256 in hex, the format GitHub uses.</summary>
        /// <param name="payload">The exact body you will send.</param>
        /// <param name="secret">The shared secret.</param>
        /// <returns>The signature header value.</returns>
        public static string Sign(string payload, string secret)
        {
            ArgumentNullException.ThrowIfNull(payload);
            return Sign(Encodings.Utf8(payload, nameof(payload)), secret);
        }

        /// <summary>Signs a payload. Returns <c>sha256=</c> followed by the HMAC-SHA256 in hex.</summary>
        /// <param name="payload">The exact body you will send.</param>
        /// <param name="secret">The shared secret.</param>
        /// <returns>The signature header value.</returns>
        public static string Sign(byte[] payload, string secret)
        {
            ArgumentNullException.ThrowIfNull(payload);
            return SignaturePrefix + Convert.ToHexStringLower(Mac(SecretBytes(secret), [], payload));
        }

        /// <summary>
        /// Checks a payload's signature. Accepts hex or Base64, with or without a <c>sha256=</c> prefix, so it works
        /// with GitHub, Shopify and most other providers that sign the body with HMAC-SHA256.
        /// </summary>
        /// <param name="payload">The exact body you received.</param>
        /// <param name="signature">The signature header. <see langword="null"/> or malformed values return <see langword="false"/>.</param>
        /// <param name="secret">The shared secret.</param>
        /// <returns><see langword="true"/> if the signature is genuine.</returns>
        public static bool Verify(string payload, [NotNullWhen(true)] string? signature, string secret)
        {
            ArgumentNullException.ThrowIfNull(payload);
            return Verify(Encodings.Utf8(payload, nameof(payload)), signature, secret);
        }

        /// <summary>Checks a payload's signature (hex or Base64, with or without a <c>sha256=</c> prefix).</summary>
        /// <param name="payload">The exact body bytes you received.</param>
        /// <param name="signature">The signature header. <see langword="null"/> or malformed values return <see langword="false"/>.</param>
        /// <param name="secret">The shared secret.</param>
        /// <returns><see langword="true"/> if the signature is genuine.</returns>
        public static bool Verify(byte[] payload, [NotNullWhen(true)] string? signature, string secret)
        {
            ArgumentNullException.ThrowIfNull(payload);
            byte[] key = SecretBytes(secret);
            if (signature is null)
            {
                return false;
            }

            ReadOnlySpan<char> value = signature.AsSpan().Trim();
            if (value.StartsWith(SignaturePrefix, StringComparison.OrdinalIgnoreCase))
            {
                value = value[SignaturePrefix.Length..];
            }

            return TryDecodeMac(value, out byte[] provided)
                && CryptographicOperations.FixedTimeEquals(provided, Mac(key, [], payload));
        }

        /// <summary>
        /// Signs a payload together with the current time, giving <c>t=&lt;unix seconds&gt;,v1=&lt;hex&gt;</c>.
        /// The receiver checks it with <see cref="VerifyWithTimestamp(string, string?, string, TimeSpan?)"/>, which
        /// also rejects old signatures, so a captured request cannot be replayed later.
        /// </summary>
        /// <param name="payload">The exact body you will send.</param>
        /// <param name="secret">The shared secret.</param>
        /// <returns>The signature header value.</returns>
        public static string SignWithTimestamp(string payload, string secret)
        {
            ArgumentNullException.ThrowIfNull(payload);
            return SignWithTimestamp(Encodings.Utf8(payload, nameof(payload)), secret, DateTimeOffset.UtcNow);
        }

        /// <summary>Signs a payload together with the current time, giving <c>t=&lt;unix seconds&gt;,v1=&lt;hex&gt;</c>.</summary>
        /// <param name="payload">The exact body you will send.</param>
        /// <param name="secret">The shared secret.</param>
        /// <returns>The signature header value.</returns>
        public static string SignWithTimestamp(byte[] payload, string secret) => SignWithTimestamp(payload, secret, DateTimeOffset.UtcNow);

        /// <summary>Checks a signature made by <see cref="SignWithTimestamp(string, string)"/> and that it is recent.</summary>
        /// <param name="payload">The exact body you received.</param>
        /// <param name="signature">The signature header. <see langword="null"/> or malformed values return <see langword="false"/>.</param>
        /// <param name="secret">The shared secret.</param>
        /// <param name="tolerance">How old (or how far in the future) the timestamp may be. Defaults to 5 minutes.</param>
        /// <returns><see langword="true"/> if the signature is genuine and recent.</returns>
        public static bool VerifyWithTimestamp(string payload, [NotNullWhen(true)] string? signature, string secret, TimeSpan? tolerance = null)
        {
            ArgumentNullException.ThrowIfNull(payload);
            return VerifyWithTimestamp(Encodings.Utf8(payload, nameof(payload)), signature, secret, tolerance ?? DefaultTolerance, DateTimeOffset.UtcNow);
        }

        /// <summary>Checks a timestamped signature over bytes and that it is recent.</summary>
        /// <param name="payload">The exact body bytes you received.</param>
        /// <param name="signature">The signature header. <see langword="null"/> or malformed values return <see langword="false"/>.</param>
        /// <param name="secret">The shared secret.</param>
        /// <param name="tolerance">How old (or how far in the future) the timestamp may be. Defaults to 5 minutes.</param>
        /// <returns><see langword="true"/> if the signature is genuine and recent.</returns>
        public static bool VerifyWithTimestamp(byte[] payload, [NotNullWhen(true)] string? signature, string secret, TimeSpan? tolerance = null) =>
            VerifyWithTimestamp(payload, signature, secret, tolerance ?? DefaultTolerance, DateTimeOffset.UtcNow);

        internal static string SignWithTimestamp(byte[] payload, string secret, DateTimeOffset now)
        {
            ArgumentNullException.ThrowIfNull(payload);
            long timestamp = now.ToUnixTimeSeconds();
            string t = timestamp.ToString(CultureInfo.InvariantCulture);
            return $"t={t},v1={Convert.ToHexStringLower(Mac(SecretBytes(secret), TimestampPrefix(t), payload))}";
        }

        internal static bool VerifyWithTimestamp(byte[] payload, string? signature, string secret, TimeSpan tolerance, DateTimeOffset now)
        {
            ArgumentNullException.ThrowIfNull(payload);
            ArgumentOutOfRangeException.ThrowIfLessThan(tolerance, TimeSpan.Zero);
            byte[] key = SecretBytes(secret);
            if (signature is null)
            {
                return false;
            }

            string? t = null;
            var candidates = new List<byte[]>(1);
            foreach (string part in signature.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
            {
                int equals = part.IndexOf('=', StringComparison.Ordinal);
                if (equals <= 0)
                {
                    continue;
                }

                ReadOnlySpan<char> name = part.AsSpan(0, equals);
                ReadOnlySpan<char> value = part.AsSpan(equals + 1);
                if (name.SequenceEqual("t"))
                {
                    t = value.ToString();
                }
                else if (name.SequenceEqual("v1") && TryDecodeMac(value, out byte[] mac))
                {
                    candidates.Add(mac); // several v1 entries are allowed, e.g. while the secret is rotated
                }
            }

            if (t is null || candidates.Count == 0
                || !long.TryParse(t, NumberStyles.None, CultureInfo.InvariantCulture, out long timestamp))
            {
                return false;
            }

            long age = now.ToUnixTimeSeconds() - timestamp;
            if (age == long.MinValue || Math.Abs(age) > (long)tolerance.TotalSeconds)
            {
                return false;
            }

            byte[] expected = Mac(key, TimestampPrefix(t), payload);
            bool valid = false;
            foreach (byte[] candidate in candidates)
            {
                valid |= CryptographicOperations.FixedTimeEquals(candidate, expected);
            }

            return valid;
        }

        private static byte[] TimestampPrefix(string t) => Encodings.Utf8(t + ".", nameof(t));

        private static byte[] Mac(byte[] key, byte[] prefix, byte[] payload)
        {
            using var hmac = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, key);
            hmac.AppendData(prefix);
            hmac.AppendData(payload);
            return hmac.GetHashAndReset();
        }

        private static byte[] SecretBytes(string secret)
        {
            ArgumentException.ThrowIfNullOrEmpty(secret);
            return Encodings.Utf8(secret, nameof(secret));
        }

        private static bool TryDecodeMac(ReadOnlySpan<char> value, out byte[] mac)
        {
            mac = [];
            if (value.Length == MacSize * 2 && Encodings.IsHex(value))
            {
                mac = Convert.FromHexString(value);
                return true;
            }

            if (value.Length is 43 or 44
                && (Encodings.TryFromBase64(value, out byte[] bytes) || Encodings.TryFromBase64Url(value, out bytes))
                && bytes.Length == MacSize)
            {
                mac = bytes;
                return true;
            }

            return false;
        }
    }
}
