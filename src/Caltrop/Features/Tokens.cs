using System.Buffers.Binary;
using System.Buffers.Text;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using CaltropSecurity.Internal;

namespace CaltropSecurity;

public static partial class Caltrop
{
    /// <summary>
    /// Encrypted, tamper-proof tokens that expire: password-reset links, email verification, invitations, "remember
    /// me" cookies or any small piece of data you hand to a user and want back unchanged.
    /// </summary>
    /// <example>
    /// <code>
    /// string token = Caltrop.Tokens.Create(user.Id, key, TimeSpan.FromHours(1), purpose: "password-reset");
    /// // ...email a link containing the token...
    ///
    /// if (Caltrop.Tokens.TryValidate(tokenFromLink, key, out string? userId, purpose: "password-reset"))
    /// {
    ///     // the link is genuine and has not expired
    /// }
    /// </code>
    /// </example>
    /// <remarks>
    /// The payload is encrypted (AES-256-GCM), so users cannot read or change it. The issue and expiry times are
    /// inside the token and protected by the same authentication tag. Tokens are URL-safe (Base64Url).
    /// </remarks>
    public static class Tokens
    {
        // version(1) kind(1) keyId(4) nonce(24) issuedAt(8) expiresAt(8)
        private const int HeaderSize = 2 + Format.KeyIdSize + Format.MessageNonceSize + 8 + 8;
        private const int Overhead = HeaderSize + Format.TagSize;
        private const int NonceOffset = 2 + Format.KeyIdSize;
        private const int IssuedAtOffset = NonceOffset + Format.MessageNonceSize;
        private const int ExpiresAtOffset = IssuedAtOffset + 8;

        private static readonly long s_maxUnixSeconds = DateTimeOffset.MaxValue.ToUnixTimeSeconds();

        /// <summary>Creates a token that carries <paramref name="payload"/> and expires after <paramref name="lifetime"/>.</summary>
        /// <param name="payload">The data to carry, for example a user id. It is encrypted, but keep it small: it makes the token longer.</param>
        /// <param name="key">The secret key.</param>
        /// <param name="lifetime">How long the token is valid. Use <see cref="TimeSpan.MaxValue"/> for a token that never expires.</param>
        /// <param name="purpose">
        /// Optional label such as <c>"password-reset"</c>. A token only validates with the same purpose, so a token
        /// made for one feature cannot be used for another.
        /// </param>
        /// <returns>The token (URL-safe text).</returns>
        public static string Create(string payload, CaltropKey key, TimeSpan lifetime, string? purpose = null) =>
            Create(payload, key, lifetime, purpose, DateTimeOffset.UtcNow);

        /// <summary>Creates a token with the default key (see <see cref="DefaultKeys"/>).</summary>
        /// <param name="payload">The data to carry.</param>
        /// <param name="lifetime">How long the token is valid.</param>
        /// <param name="purpose">Optional label; the token only validates with the same purpose.</param>
        /// <returns>The token (URL-safe text).</returns>
        public static string Create(string payload, TimeSpan lifetime, string? purpose = null) =>
            Create(payload, DefaultKeys.Primary, lifetime, purpose, DateTimeOffset.UtcNow);

        /// <summary>Checks a token and returns its payload.</summary>
        /// <param name="token">The token.</param>
        /// <param name="key">The key it was created with.</param>
        /// <param name="purpose">The purpose it was created with, if any.</param>
        /// <returns>The payload.</returns>
        /// <exception cref="CaltropException">
        /// The token is damaged, forged, made with another key or purpose (<see cref="CaltropErrorCode.AuthenticationFailed"/>
        /// or <see cref="CaltropErrorCode.KeyMismatch"/>), or has expired (<see cref="CaltropErrorCode.TokenExpired"/>).
        /// </exception>
        public static string Validate(string token, CaltropKey key, string? purpose = null) =>
            Validate(token, KeyList.Single(key, nameof(key)), purpose, DateTimeOffset.UtcNow);

        /// <summary>Checks a token made with any key in <paramref name="keys"/>. Use this during key rotation.</summary>
        /// <param name="token">The token.</param>
        /// <param name="keys">The candidate keys, for example a <see cref="CaltropKeyRing"/>.</param>
        /// <param name="purpose">The purpose it was created with, if any.</param>
        /// <returns>The payload.</returns>
        /// <exception cref="CaltropException">The token is invalid or has expired.</exception>
        public static string Validate(string token, IEnumerable<CaltropKey> keys, string? purpose = null) =>
            Validate(token, KeyList.From(keys, nameof(keys)), purpose, DateTimeOffset.UtcNow);

        /// <summary>Checks a token made with the default keys (see <see cref="DefaultKeys"/>).</summary>
        /// <param name="token">The token.</param>
        /// <param name="purpose">The purpose it was created with, if any.</param>
        /// <returns>The payload.</returns>
        /// <exception cref="CaltropException">The token is invalid or has expired.</exception>
        public static string Validate(string token, string? purpose = null) =>
            Validate(token, DefaultKeys, purpose, DateTimeOffset.UtcNow);

        /// <summary>Checks a token without throwing.</summary>
        /// <param name="token">The token, for example from a query string. <see langword="null"/> returns <see langword="false"/>.</param>
        /// <param name="key">The key it was created with.</param>
        /// <param name="payload">The payload if the token is valid; otherwise <see langword="null"/>.</param>
        /// <param name="purpose">The purpose it was created with, if any.</param>
        /// <returns><see langword="true"/> if the token is genuine, has the right purpose and has not expired.</returns>
        public static bool TryValidate([NotNullWhen(true)] string? token, CaltropKey key, [NotNullWhen(true)] out string? payload, string? purpose = null) =>
            TryValidate(token, KeyList.Single(key, nameof(key)), purpose, DateTimeOffset.UtcNow, out payload);

        /// <summary>Checks a token made with any key in <paramref name="keys"/>, without throwing.</summary>
        /// <param name="token">The token. <see langword="null"/> returns <see langword="false"/>.</param>
        /// <param name="keys">The candidate keys.</param>
        /// <param name="payload">The payload if the token is valid; otherwise <see langword="null"/>.</param>
        /// <param name="purpose">The purpose it was created with, if any.</param>
        /// <returns><see langword="true"/> if the token is genuine, has the right purpose and has not expired.</returns>
        public static bool TryValidate([NotNullWhen(true)] string? token, IEnumerable<CaltropKey> keys, [NotNullWhen(true)] out string? payload, string? purpose = null) =>
            TryValidate(token, KeyList.From(keys, nameof(keys)), purpose, DateTimeOffset.UtcNow, out payload);

        /// <summary>Checks a token made with the default keys (see <see cref="DefaultKeys"/>), without throwing.</summary>
        /// <param name="token">The token. <see langword="null"/> returns <see langword="false"/>.</param>
        /// <param name="payload">The payload if the token is valid; otherwise <see langword="null"/>.</param>
        /// <param name="purpose">The purpose it was created with, if any.</param>
        /// <returns><see langword="true"/> if the token is genuine, has the right purpose and has not expired.</returns>
        public static bool TryValidate([NotNullWhen(true)] string? token, [NotNullWhen(true)] out string? payload, string? purpose = null) =>
            TryValidate(token, DefaultKeys, purpose, DateTimeOffset.UtcNow, out payload);

        internal static string Create(string payload, CaltropKey key, TimeSpan lifetime, string? purpose, DateTimeOffset now)
        {
            ArgumentNullException.ThrowIfNull(payload);
            ArgumentNullException.ThrowIfNull(key);
            ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(lifetime, TimeSpan.Zero);
            key.ThrowIfDisposed();
            Aead.EnsureSupported();

            byte[] plaintext = Encodings.Utf8(payload, nameof(payload));
            byte[] aad = Encodings.Utf8(purpose, nameof(purpose));
            long issuedAt = now.ToUnixTimeSeconds();
            double lifetimeSeconds = Math.Ceiling(lifetime.TotalSeconds);
            long expiresAt = lifetimeSeconds >= s_maxUnixSeconds - issuedAt ? s_maxUnixSeconds : issuedAt + (long)lifetimeSeconds;

            byte[] output = new byte[Overhead + plaintext.Length];
            Span<byte> header = output.AsSpan(0, HeaderSize);
            header[0] = Format.Version;
            header[1] = (byte)BlobKind.Token;
            key.IdBytes.CopyTo(header[2..]);
            Span<byte> nonce = header.Slice(NonceOffset, Format.MessageNonceSize);
            RandomNumberGenerator.Fill(nonce);
            BinaryPrimitives.WriteInt64BigEndian(header[IssuedAtOffset..], issuedAt);
            BinaryPrimitives.WriteInt64BigEndian(header[ExpiresAtOffset..], expiresAt);

            Span<byte> tokenKey = stackalloc byte[Format.KeySize];
            try
            {
                key.Derive(Labels.Token, nonce, tokenKey);
                Aead.Seal(tokenKey, nonce[..Format.GcmNonceSize], plaintext, output.AsSpan(HeaderSize, plaintext.Length), output.AsSpan(HeaderSize + plaintext.Length), header, aad);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(tokenKey);
                CryptographicOperations.ZeroMemory(plaintext);
            }

            return Base64Url.EncodeToString(output);
        }

        internal static string Validate(string token, IReadOnlyList<CaltropKey> keys, string? purpose, DateTimeOffset now)
        {
            ArgumentNullException.ThrowIfNull(token);
            byte[] data = Encodings.FromBase64Url(token);
            Errors.ExpectKind(data, BlobKind.Token);
            if (data.Length < Overhead)
            {
                throw Errors.Truncated();
            }

            Aead.EnsureSupported();
            ReadOnlySpan<byte> header = data.AsSpan(0, HeaderSize);
            ReadOnlySpan<byte> keyId = header.Slice(2, Format.KeyIdSize);
            ReadOnlySpan<byte> nonce = header.Slice(NonceOffset, Format.MessageNonceSize);
            byte[] aad = Encodings.Utf8(purpose, nameof(purpose));

            bool anyMatch = false;
            Span<byte> tokenKey = stackalloc byte[Format.KeySize];
            try
            {
                foreach (CaltropKey key in keys)
                {
                    if (!key.Matches(keyId))
                    {
                        continue;
                    }

                    anyMatch = true;
                    key.Derive(Labels.Token, nonce, tokenKey);
                    byte[] plaintext = new byte[data.Length - Overhead];
                    if (!Aead.TryOpen(tokenKey, nonce[..Format.GcmNonceSize], data.AsSpan(HeaderSize, plaintext.Length), data.AsSpan(data.Length - Format.TagSize), plaintext, header, aad))
                    {
                        continue;
                    }

                    // Expiry is only checked once the token is known to be genuine.
                    long expiresAt = BinaryPrimitives.ReadInt64BigEndian(header[ExpiresAtOffset..]);
                    if (now.ToUnixTimeSeconds() >= expiresAt)
                    {
                        throw Errors.TokenExpired(DateTimeOffset.FromUnixTimeSeconds(Math.Clamp(expiresAt, 0, s_maxUnixSeconds)));
                    }

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
            finally
            {
                CryptographicOperations.ZeroMemory(tokenKey);
            }

            throw anyMatch
                ? new CaltropException(CaltropErrorCode.AuthenticationFailed, "The token is not valid: it was changed or forged, or it was created for a different purpose.")
                : Errors.KeyMismatch(keyId, keys.Count);
        }

        internal static bool TryValidate([NotNullWhen(true)] string? token, IReadOnlyList<CaltropKey> keys, string? purpose, DateTimeOffset now, [NotNullWhen(true)] out string? payload)
        {
            payload = null;
            if (string.IsNullOrEmpty(token))
            {
                return false;
            }

            try
            {
                payload = Validate(token, keys, purpose, now);
                return true;
            }
            catch (CaltropException)
            {
                return false;
            }
        }
    }
}
