using System.Buffers.Binary;
using System.Buffers.Text;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using CaltropSecurity.Internal;

public static partial class Caltrop
{
    /// <summary>
    /// Decoys: fake secrets that look exactly like real ones but should never be used. Plant them where an attacker
    /// would look. If anyone ever uses one, Caltrop recognizes it and sets off a
    /// <see cref="CaltropAlarmKind.DecoyUsed"/> alarm (see <see cref="Traps"/>).
    /// </summary>
    /// <example>
    /// <code>
    /// // A fake admin account: anyone who tries to log in to it trips the alarm.
    /// db.Users.Add(new User { Name = "admin", PasswordHash = Caltrop.Decoys.PasswordHash() });
    ///
    /// // A fake API key planted in an old config file or a test repository.
    /// string bait = Caltrop.Decoys.ApiKey("acme_live");
    ///
    /// // A fake credit card row: decrypting it through your app trips the alarm.
    /// db.Cards.Add(new Card { Number = Caltrop.Decoys.Encrypted("4111 1111 1111 1111") });
    /// </code>
    /// </example>
    /// <remarks>
    /// Decoys carry a hidden mark made with your default key (<see cref="UseKey(CaltropKey)"/> or <c>CALTROP_KEY</c>), so only your
    /// app can tell them apart from real values. Caltrop checks for them by itself in
    /// <see cref="Passwords.Verify(string, string)"/>, the <see cref="ApiKeys"/> methods and <see cref="Decrypt(string)"/>:
    /// you do not need to change any other code. Decoy passwords and API keys never work; a decoy encrypted value
    /// decrypts to its fake content, so the attacker does not notice they were caught.
    /// </remarks>
    public static class Decoys
    {
        private const int PasswordSaltRandomSize = 8;
        private const int ApiKeyRandomChars = 21;
        private const int ApiKeyMarkChars = 11;
        private const int MessageMarkSize = Format.MessageNonceSize - Format.GcmNonceSize;

        private static readonly ConcurrentDictionary<string, string> s_watched = new(StringComparer.Ordinal);

        /// <summary>
        /// Creates a decoy password hash for a fake account. It looks like any other hash from
        /// <see cref="Passwords.Hash(string)"/>, but no password matches it, and any login attempt against it trips the alarm.
        /// </summary>
        /// <returns>The hash to store on the fake account.</returns>
        /// <exception cref="InvalidOperationException">No default key is set.</exception>
        public static string PasswordHash()
        {
            CaltropKey key = DefaultKeys.Primary;
            Span<byte> salt = stackalloc byte[PasswordKdf.SaltSize];
            RandomNumberGenerator.Fill(salt[..PasswordSaltRandomSize]);
            DecoyMarks.Compute(key, DecoyMarks.PasswordHash, salt[..PasswordSaltRandomSize], salt[PasswordSaltRandomSize..]);
            Span<byte> hash = stackalloc byte[32];
            RandomNumberGenerator.Fill(hash);
            return Passwords.Format(PasswordKdf.DefaultIterations, salt, hash);
        }

        /// <summary>
        /// Creates a decoy API key. It has the same shape and a valid checksum like any key from
        /// <see cref="ApiKeys.Generate(string)"/>, but it never works, and using it trips the alarm.
        /// </summary>
        /// <param name="prefix">The same prefix your real keys use, such as <c>"acme_live"</c>, so it looks genuine.</param>
        /// <returns>The decoy key. Plant it; do not store its hash.</returns>
        /// <exception cref="InvalidOperationException">No default key is set.</exception>
        public static string ApiKey(string prefix)
        {
            ApiKeys.ValidatePrefix(prefix);
            CaltropKey key = DefaultKeys.Primary;
            string random = RandomNumberGenerator.GetString(Base62.Alphabet, ApiKeyRandomChars);
            return ApiKeys.Assemble(prefix, random + ApiKeyMark(key, prefix, random));
        }

        /// <summary>
        /// Creates a decoy encrypted value that looks like any other value from <see cref="Encrypt(string)"/>.
        /// Decrypting it through Caltrop returns <paramref name="fakeValue"/> and trips the alarm.
        /// </summary>
        /// <param name="fakeValue">What it decrypts to: something tempting but fake, like a test card number.</param>
        /// <param name="key">The key your real data uses. Defaults to the default key.</param>
        /// <param name="context">The same context your real data uses, if any.</param>
        /// <returns>The encrypted decoy, to store among your real data.</returns>
        public static string Encrypted(string fakeValue, CaltropKey? key = null, string? context = null)
        {
            ArgumentNullException.ThrowIfNull(fakeValue);
            key ??= DefaultKeys.Primary;
            byte[] bytes = Encodings.Utf8(fakeValue, nameof(fakeValue));
            return Base64Url.EncodeToString(SecretKeyMessages.Encrypt(bytes, key, Encodings.Utf8(context, nameof(context)), decoy: true));
        }

        /// <summary>
        /// Watches a value of your own, such as a fake user name, email address or record id. Pass values you
        /// receive to <see cref="Check(string?)"/>; a watched one trips the alarm.
        /// </summary>
        /// <param name="value">The decoy value. Matched exactly (case-sensitive).</param>
        /// <param name="label">Optional. A name for it that appears in the alarm, such as <c>"fake CEO email"</c>.</param>
        /// <remarks>Watched values live in memory: call this when your app starts.</remarks>
        public static void Watch(string value, string? label = null)
        {
            ArgumentException.ThrowIfNullOrEmpty(value);
            s_watched[value] = label ?? "watched value";
        }

        /// <summary>
        /// Checks whether a value is a decoy: a watched value, or a decoy password hash, API key or encrypted value.
        /// If it is, the alarm goes off.
        /// </summary>
        /// <param name="value">Any value from outside your app.</param>
        /// <returns><see langword="true"/> if it is a decoy (the alarm has gone off).</returns>
        public static bool Check(string? value)
        {
            if (string.IsNullOrEmpty(value))
            {
                return false;
            }

            if (s_watched.TryGetValue(value, out string? label))
            {
                Traps.Raise(CaltropAlarmKind.DecoyUsed, "Watched value", $"A watched decoy value was used ({label}).", label);
                return true;
            }

            if (Passwords.TryParse(value, out _, out byte[] salt, out _) && IsDecoySalt(salt))
            {
                RaisePasswordAlarm();
                return true;
            }

            if (IsDecoyApiKey(value))
            {
                RaiseApiKeyAlarm(value);
                return true;
            }

            if (Encodings.TryFromBase64Url(value.AsSpan().Trim(), out byte[] data) && IsDecoyMessageForDefaultKeys(data))
            {
                RaiseMessageAlarm();
                return true;
            }

            return false;
        }

        /// <summary>Forgets every watched value (tests only).</summary>
        internal static void ClearWatched() => s_watched.Clear();

        internal static bool IsDecoySalt(ReadOnlySpan<byte> salt) =>
            salt.Length == PasswordKdf.SaltSize
            && DecoyMarks.MatchesAnyDefaultKey(DecoyMarks.PasswordHash, salt[..PasswordSaltRandomSize], salt[PasswordSaltRandomSize..]);

        /// <summary>Recognizes a well-formed key whose random part carries a decoy mark from a default key.</summary>
        internal static bool IsDecoyApiKey(string apiKey)
        {
            if (!ApiKeys.TrySplit(apiKey, out string prefix, out string random))
            {
                return false;
            }

            CaltropKeyRing? keys = TryGetDefaultKeys();
            if (keys is null)
            {
                return false;
            }

            string randomHalf = random[..ApiKeyRandomChars];
            byte[] actual = Encoding.ASCII.GetBytes(random[ApiKeyRandomChars..]);
            foreach (CaltropKey key in keys)
            {
                try
                {
                    if (CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(ApiKeyMark(key, prefix, randomHalf)), actual))
                    {
                        return true;
                    }
                }
                catch (ObjectDisposedException)
                {
                }
            }

            return false;
        }

        /// <summary>Makes a message nonce: 12 random bytes (the GCM nonce), then their decoy mark.</summary>
        internal static void FillDecoyNonce(CaltropKey key, Span<byte> nonce)
        {
            RandomNumberGenerator.Fill(nonce[..Format.GcmNonceSize]);
            DecoyMarks.Compute(key, DecoyMarks.Message, nonce[..Format.GcmNonceSize], nonce[Format.GcmNonceSize..]);
        }

        internal static bool IsDecoyNonce(CaltropKey key, ReadOnlySpan<byte> nonce) =>
            DecoyMarks.Matches(key, DecoyMarks.Message, nonce[..Format.GcmNonceSize], nonce[Format.GcmNonceSize..(Format.GcmNonceSize + MessageMarkSize)]);

        internal static void RaisePasswordAlarm() =>
            Traps.Raise(CaltropAlarmKind.DecoyUsed, "Decoy password", "Someone tried to log in to a decoy account. They may have a copy of your user database.", subject: null);

        internal static void RaiseApiKeyAlarm(string apiKey) =>
            Traps.Raise(CaltropAlarmKind.DecoyUsed, "Decoy API key", $"A decoy API key was used ({apiKey}). Someone may have stolen it from where it was planted.", apiKey);

        internal static void RaiseMessageAlarm() =>
            Traps.Raise(CaltropAlarmKind.DecoyUsed, "Decoy data", "A decoy encrypted value was decrypted. Someone may be reading data they should not.", subject: null);

        private static string ApiKeyMark(CaltropKey key, string prefix, string randomHalf)
        {
            Span<byte> mark = stackalloc byte[8];
            DecoyMarks.Compute(key, DecoyMarks.ApiKey, Encoding.ASCII.GetBytes($"{prefix}_{randomHalf}"), mark);
            return Base62.EncodeUInt64(BinaryPrimitives.ReadUInt64BigEndian(mark));
        }

        private static bool IsDecoyMessageForDefaultKeys(ReadOnlySpan<byte> data)
        {
            if (data.Length < SecretKeyMessages.Overhead || data[0] != Format.Version || data[1] != (byte)BlobKind.SecretKeyMessage)
            {
                return false;
            }

            CaltropKeyRing? keys = TryGetDefaultKeys();
            if (keys is null)
            {
                return false;
            }

            ReadOnlySpan<byte> keyId = data.Slice(2, Format.KeyIdSize);
            ReadOnlySpan<byte> nonce = data.Slice(2 + Format.KeyIdSize, Format.MessageNonceSize);
            foreach (CaltropKey key in keys)
            {
                try
                {
                    if (key.Matches(keyId) && IsDecoyNonce(key, nonce))
                    {
                        return true;
                    }
                }
                catch (ObjectDisposedException)
                {
                }
            }

            return false;
        }
    }
}
