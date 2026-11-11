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

    public static bool IsHex(ReadOnlySpan<char> text) => !text.IsEmpty && !text.ContainsAnyExcept(HexChars);

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

    /// <summary>Decodes Base64Url text produced by Caltrop, trimming surrounding whitespace.</summary>
    public static byte[] FromBase64Url(string text)
    {
        try
        {
            return Base64Url.DecodeFromChars(text.AsSpan().Trim());
        }
        catch (FormatException ex)
        {
            throw Errors.NotBase64Url(ex);
        }
    }

    /// <summary>Decodes Base64Url without throwing. (Base64Url.TryDecodeFromChars itself throws on invalid characters.)</summary>
    public static bool TryFromBase64Url(ReadOnlySpan<char> text, out byte[] bytes)
    {
        bytes = [];
        text = text.Trim();
        if (!Base64Url.IsValid(text, out int decodedLength))
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

    /// <summary>Decodes standard Base64, with or without padding.</summary>
    public static bool TryFromBase64(ReadOnlySpan<char> text, out byte[] bytes)
    {
        bytes = [];
        if (text.IsEmpty || text.Length % 4 == 1)
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

        bytes = buffer[..written];
        return true;
    }
}

/// <summary>RFC 4648 Base32 (used for TOTP secrets). Encodes without padding; decoding ignores case, spaces, dashes and padding.</summary>
internal static class Base32
{
    private const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    public static string Encode(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty)
        {
            return string.Empty;
        }

        var result = new StringBuilder((data.Length * 8 + 4) / 5);
        int buffer = 0;
        int bitsLeft = 0;
        foreach (byte b in data)
        {
            buffer = (buffer << 8) | b;
            bitsLeft += 8;
            while (bitsLeft >= 5)
            {
                result.Append(Alphabet[(buffer >> (bitsLeft - 5)) & 0x1F]);
                bitsLeft -= 5;
            }
        }

        if (bitsLeft > 0)
        {
            result.Append(Alphabet[(buffer << (5 - bitsLeft)) & 0x1F]);
        }

        return result.ToString();
    }

    public static bool TryDecode(ReadOnlySpan<char> text, out byte[] bytes)
    {
        var output = new List<byte>(text.Length * 5 / 8);
        int buffer = 0;
        int bitsLeft = 0;
        bool sawPadding = false;
        foreach (char raw in text)
        {
            if (raw is ' ' or '-' or '\t')
            {
                continue;
            }

            if (raw == '=')
            {
                sawPadding = true;
                continue;
            }

            if (sawPadding)
            {
                bytes = [];
                return false; // data after padding
            }

            char c = char.ToUpperInvariant(raw);
            int value = c switch
            {
                >= 'A' and <= 'Z' => c - 'A',
                >= '2' and <= '7' => c - '2' + 26,
                _ => -1,
            };
            if (value < 0)
            {
                bytes = [];
                return false;
            }

            buffer = (buffer << 5) | value;
            bitsLeft += 5;
            if (bitsLeft >= 8)
            {
                output.Add((byte)(buffer >> (bitsLeft - 8)));
                bitsLeft -= 8;
            }

            buffer &= (1 << bitsLeft) - 1;
        }

        bytes = [.. output];
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

    public static bool IsBase62(ReadOnlySpan<char> text) => !text.IsEmpty && !text.ContainsAnyExcept(s_chars);
}
