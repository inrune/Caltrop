using System.Buffers;
using System.Buffers.Text;
using System.Text;

namespace CaltropSecurity.Internal;

/// <summary>Text encodings used across Caltrop.</summary>
internal static class Encodings
{
    /// <summary>UTF-8 that throws on invalid bytes instead of silently inserting U+FFFD.</summary>
    public static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    public static readonly SearchValues<char> HexChars = SearchValues.Create("0123456789abcdefABCDEF");

    private static readonly SearchValues<char> s_lowerHexChars = SearchValues.Create("0123456789abcdef");

    private static readonly SearchValues<char> s_base64UrlChars = SearchValues.Create("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_");

    public static bool IsHex(ReadOnlySpan<char> text) => !text.IsEmpty && !text.ContainsAnyExcept(HexChars);

    /// <summary>Hex as Caltrop writes it: lowercase only.</summary>
    public static bool IsLowercaseHex(ReadOnlySpan<char> text) => !text.IsEmpty && !text.ContainsAnyExcept(s_lowerHexChars);

    /// <summary>
    /// <see langword="false"/> if the text contains half of a surrogate pair. Such text cannot be stored as UTF-8
    /// without changing it, so it can never be a real password or key: browsers cannot even send it.
    /// </summary>
    public static bool IsValidUnicode(ReadOnlySpan<char> text)
    {
        for (int i = 0; i < text.Length; i++)
        {
            if (char.IsHighSurrogate(text[i]) && i + 1 < text.Length && char.IsLowSurrogate(text[i + 1]))
            {
                i++;
            }
            else if (char.IsSurrogate(text[i]))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>Strict UTF-8 encoding. Text with unpaired surrogates is rejected rather than silently changed.</summary>
    public static byte[] Utf8(string? text, string parameterName)
    {
        if (string.IsNullOrEmpty(text))
        {
            return [];
        }

        try
        {
            return StrictUtf8.GetBytes(text);
        }
        catch (EncoderFallbackException ex)
        {
            throw new ArgumentException(
                "The text contains invalid Unicode (an unpaired surrogate character), so it cannot be stored as UTF-8 without changing it. Convert it to bytes yourself and use the byte[] overload.",
                parameterName,
                ex);
        }
    }

    public static string DecodeUtf8(ReadOnlySpan<byte> bytes)
    {
        try
        {
            return StrictUtf8.GetString(bytes);
        }
        catch (DecoderFallbackException ex)
        {
            throw new CaltropException(
                CaltropErrorCode.InvalidFormat,
                "The decrypted data is not UTF-8 text. It was probably encrypted from bytes, so decrypt it with the byte[] overload.",
                ex);
        }
    }

    /// <summary>
    /// Decodes Base64Url text produced by Caltrop. Whitespace around it is ignored, but nothing else: no spaces or line
    /// breaks inside and no padding, which .NET would otherwise accept. So every value has exactly one text form, and
    /// a changed text is never mistaken for the original.
    /// </summary>
    public static byte[] FromBase64Url(string text)
    {
        ReadOnlySpan<char> span = text.AsSpan().Trim();
        if (span.ContainsAnyExcept(s_base64UrlChars))
        {
            throw Errors.NotBase64Url(null);
        }

        try
        {
            return Base64Url.DecodeFromChars(span);
        }
        catch (FormatException ex)
        {
            throw Errors.NotBase64Url(ex);
        }
    }

    /// <summary>
    /// Decodes Base64Url like <see cref="FromBase64Url"/>, without throwing, and without trimming: trim the whole value
    /// once yourself, so that nothing can hide inside it (such as a space after a "ctk_" prefix).
    /// </summary>
    public static bool TryFromBase64Url(ReadOnlySpan<char> text, out byte[] bytes)
    {
        bytes = [];
        if (text.ContainsAnyExcept(s_base64UrlChars) || !Base64Url.IsValid(text, out int decodedLength))
        {
            return false;
        }

        var buffer = new byte[decodedLength];
        try
        {
            if (!Base64Url.TryDecodeFromChars(text, buffer, out int written))
            {
                return false;
            }

            bytes = written == buffer.Length ? buffer : buffer[..written];
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    /// <summary>Standard Base64 without padding, as used by the PHC string format.</summary>
    public static string ToBase64NoPadding(ReadOnlySpan<byte> bytes) => Convert.ToBase64String(bytes).TrimEnd('=');

    /// <summary>
    /// Decodes standard Base64. Only the standard spelling counts: .NET would also skip whitespace inside, and accept
    /// a different last character for the same bytes.
    /// </summary>
    /// <param name="text">The text.</param>
    /// <param name="bytes">The decoded bytes.</param>
    /// <param name="allowPadding">Whether full padding is also accepted. Without it, there must be none.</param>
    public static bool TryFromBase64(ReadOnlySpan<char> text, out byte[] bytes, bool allowPadding = true)
    {
        bytes = [];
        if (text.IsEmpty || text.Length % 4 == 1 || (text.Contains('=') && (!allowPadding || text.Length % 4 != 0)))
        {
            return false;
        }

        int padding = (4 - (text.Length % 4)) % 4;
        Span<char> padded = text.Length + padding <= 512 ? stackalloc char[text.Length + padding] : new char[text.Length + padding];
        text.CopyTo(padded);
        padded[text.Length..].Fill('=');

        var buffer = new byte[(padded.Length / 4) * 3];
        if (!Convert.TryFromBase64Chars(padded, buffer, out int written))
        {
            return false;
        }

        // Re-encoding must give back exactly the input.
        if (!Convert.ToBase64String(buffer, 0, written).AsSpan().TrimEnd('=').SequenceEqual(text.TrimEnd('=')))
        {
            return false;
        }

        bytes = buffer[..written];
        return true;
    }
}

/// <summary>Base62 digits (0-9, A-Z, a-z): letters and numbers only, safe to double-click and copy.</summary>
internal static class Base62
{
    public const string Alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    private static readonly SearchValues<char> s_chars = SearchValues.Create(Alphabet);

    /// <summary>Encodes a 32-bit value as exactly 6 Base62 digits (62^6 &gt; 2^32).</summary>
    public static string EncodeUInt32(uint value)
    {
        Span<char> chars = stackalloc char[6];
        for (int i = chars.Length - 1; i >= 0; i--)
        {
            chars[i] = Alphabet[(int)(value % 62)];
            value /= 62;
        }

        return new string(chars);
    }

    /// <summary>Encodes a 64-bit value as exactly 11 Base62 digits (62^11 &gt; 2^64).</summary>
    public static string EncodeUInt64(ulong value)
    {
        Span<char> chars = stackalloc char[11];
        for (int i = chars.Length - 1; i >= 0; i--)
        {
            chars[i] = Alphabet[(int)(value % 62)];
            value /= 62;
        }

        return new string(chars);
    }

    public static bool IsBase62(ReadOnlySpan<char> text) => !text.IsEmpty && !text.ContainsAnyExcept(s_chars);
}
