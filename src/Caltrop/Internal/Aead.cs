using System.Security.Cryptography;

namespace CaltropSecurity.Internal;

/// <summary>AES-256-GCM with Caltrop's associated-data convention: AAD = header || caller's associated data.</summary>
internal static class Aead
{
    public static void EnsureSupported()
    {
        if (!AesGcm.IsSupported)
        {
            throw new PlatformNotSupportedException(
                "AES-GCM is not available on this platform (for example Blazor WebAssembly), so Caltrop cannot encrypt here.");
        }
    }

    public static void Seal(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> plaintext,
        Span<byte> ciphertext,
        Span<byte> tag,
        ReadOnlySpan<byte> header,
        ReadOnlySpan<byte> associatedData)
    {
        using var aes = new AesGcm(key, Format.TagSize);
        if (associatedData.IsEmpty)
        {
            aes.Encrypt(nonce, plaintext, ciphertext, tag, header);
        }
        else
        {
            aes.Encrypt(nonce, plaintext, ciphertext, tag, Concat(header, associatedData));
        }
    }

    /// <summary>Returns <see langword="false"/> (and leaves <paramref name="plaintext"/> zeroed) if authentication fails.</summary>
    public static bool TryOpen(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> tag,
        Span<byte> plaintext,
        ReadOnlySpan<byte> header,
        ReadOnlySpan<byte> associatedData)
    {
        using var aes = new AesGcm(key, Format.TagSize);
        try
        {
            if (associatedData.IsEmpty)
            {
                aes.Decrypt(nonce, ciphertext, tag, plaintext, header);
            }
            else
            {
                aes.Decrypt(nonce, ciphertext, tag, plaintext, Concat(header, associatedData));
            }

            return true;
        }
        catch (AuthenticationTagMismatchException)
        {
            return false;
        }
    }

    private static byte[] Concat(ReadOnlySpan<byte> first, ReadOnlySpan<byte> second)
    {
        var result = new byte[first.Length + second.Length];
        first.CopyTo(result);
        second.CopyTo(result.AsSpan(first.Length));
        return result;
    }
}
