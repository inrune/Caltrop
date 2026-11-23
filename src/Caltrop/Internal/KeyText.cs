using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;

namespace CaltropSecurity.Internal;

/// <summary>
/// Key strings look like <c>prefix + Base64Url(payload || checksum)</c>, where the checksum is the first 4 bytes of
/// SHA-256(prefix || payload). The checksum catches typos and truncation with a clear error before the key is used.
/// </summary>
internal static class KeyText
{
    private const int ChecksumSize = 4;

    public static string Encode(string prefix, ReadOnlySpan<byte> payload)
    {
        byte[] buffer = new byte[payload.Length + ChecksumSize];
        try
        {
            payload.CopyTo(buffer);
            ComputeChecksum(prefix, payload, buffer.AsSpan(payload.Length));
            return prefix + Base64Url.EncodeToString(buffer);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
    }

    /// <summary>Decodes and checks a key string. On success the caller owns (and should zero) the returned payload.</summary>
    public static bool TryDecode(string text, string prefix, int payloadSize, out byte[] payload, out string error)
    {
        payload = [];
        ReadOnlySpan<char> span = text.AsSpan().Trim();
        if (!span.StartsWith(prefix, StringComparison.Ordinal))
        {
            error = $"Expected a key starting with \"{prefix}\".";
            return false;
        }

        if (!Encodings.TryFromBase64Url(span[prefix.Length..], out byte[] decoded) || decoded.Length != payloadSize + ChecksumSize)
        {
            CryptographicOperations.ZeroMemory(decoded);
            error = $"The key text after \"{prefix}\" is damaged or incomplete. Make sure the whole key was copied.";
            return false;
        }

        Span<byte> expected = stackalloc byte[ChecksumSize];
        ComputeChecksum(prefix, decoded.AsSpan(0, payloadSize), expected);
        if (!CryptographicOperations.FixedTimeEquals(expected, decoded.AsSpan(payloadSize)))
        {
            CryptographicOperations.ZeroMemory(decoded);
            error = "The key failed its checksum: at least one character was changed. Copy the key again.";
            return false;
        }

        payload = decoded[..payloadSize];
        CryptographicOperations.ZeroMemory(decoded);
        error = string.Empty;
        return true;
    }

    private static void ComputeChecksum(string prefix, ReadOnlySpan<byte> payload, Span<byte> destination)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(Encoding.ASCII.GetBytes(prefix));
        hash.AppendData(payload);
        Span<byte> digest = stackalloc byte[32];
        hash.GetHashAndReset(digest);
        digest[..ChecksumSize].CopyTo(destination);
    }
}
