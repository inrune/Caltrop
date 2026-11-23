using System.Security.Cryptography;

namespace CaltropSecurity.Internal;

/// <summary>
/// The hidden mark that makes a decoy recognizable. A decoy's random-looking part is split into a random half and a
/// mark: mark = HMAC-SHA256(HKDF-Expand(K, "caltrop/v1/decoy:" || domain), random half), truncated. Without the key
/// the mark looks like any other random bytes, so a decoy cannot be told apart from the real thing.
/// </summary>
internal static class DecoyMarks
{
    public static ReadOnlySpan<byte> PasswordHash => "password-hash"u8;
    public static ReadOnlySpan<byte> ApiKey => "api-key"u8;
    public static ReadOnlySpan<byte> Message => "message"u8;

    public static void Compute(CaltropKey key, ReadOnlySpan<byte> domain, ReadOnlySpan<byte> data, Span<byte> mark)
    {
        Span<byte> markKey = stackalloc byte[Format.KeySize];
        Span<byte> mac = stackalloc byte[32];
        try
        {
            key.Derive(Labels.Decoy, domain, markKey);
            HMACSHA256.HashData(markKey, data, mac);
            mac[..mark.Length].CopyTo(mark);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(markKey);
            CryptographicOperations.ZeroMemory(mac);
        }
    }

    public static bool Matches(CaltropKey key, ReadOnlySpan<byte> domain, ReadOnlySpan<byte> data, ReadOnlySpan<byte> mark)
    {
        Span<byte> expected = stackalloc byte[mark.Length];
        Compute(key, domain, data, expected);
        return CryptographicOperations.FixedTimeEquals(expected, mark);
    }

    /// <summary>Checks the mark against every default key. <see langword="false"/> if no default key is set.</summary>
    public static bool MatchesAnyDefaultKey(ReadOnlySpan<byte> domain, ReadOnlySpan<byte> data, ReadOnlySpan<byte> mark)
    {
        CaltropKeyRing? keys = Caltrop.TryGetDefaultKeys();
        if (keys is null)
        {
            return false;
        }

        foreach (CaltropKey key in keys)
        {
            try
            {
                if (Matches(key, domain, data, mark))
                {
                    return true;
                }
            }
            catch (ObjectDisposedException)
            {
                // A disposed default key cannot mark anything.
            }
        }

        return false;
    }
}
