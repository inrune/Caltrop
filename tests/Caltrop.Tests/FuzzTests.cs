using System.Buffers.Binary;
using System.Text;
using CaltropSecurity.Internal;

namespace CaltropSecurity.Tests;

/// <summary>
/// Feeds damaged and random versions of every kind of Caltrop data back into the method that reads it. The only
/// acceptable answers are "no" (false, or a <see cref="CaltropException"/>) and, for an unchanged value, "yes":
/// never another kind of exception, and never "yes" for something that was changed.
/// </summary>
/// <remarks>
/// For a longer search, set CALTROP_FUZZ_SEED to any number and CALTROP_FUZZ_ROUNDS to how many times more
/// changes to try (for example 100), then run the tests. A failure prints the input, so it can be repeated.
/// </remarks>
public sealed class FuzzTests : IDisposable
{
    private readonly CaltropKey _key = CaltropKey.Generate();
    private readonly TempFolder _folder = new();
    private readonly Fuzzer _fuzz = new(
        seed: int.TryParse(Environment.GetEnvironmentVariable("CALTROP_FUZZ_SEED"), out int seed) ? seed : 20261123,
        scale: int.TryParse(Environment.GetEnvironmentVariable("CALTROP_FUZZ_ROUNDS"), out int scale) && scale > 0 ? scale : 1);

    public void Dispose() => _folder.Dispose();

    [Fact]
    public void Encrypted_text()
    {
        string valid = Caltrop.Encrypt("a secret", _key);
        _fuzz.Text(valid, text => Caltrop.Decrypt(text, _key) == "a secret");
        _fuzz.Text(Caltrop.Encrypt("a secret", _key, context: "user 7"), text => Caltrop.Decrypt(text, _key, context: "user 7") == "a secret");
    }

    [Fact]
    public void Encrypted_bytes()
    {
        byte[] valid = Caltrop.Encrypt([1, 2, 3], _key);
        _fuzz.Bytes(valid, data => Caltrop.Decrypt(data, _key).Length == 3);
    }

    [Fact]
    public void Encrypted_with_a_password()
    {
        byte[] valid = PasswordMessages.Encrypt("a secret"u8, "a long password 2026", iterations: 1000);
        _fuzz.Bytes(valid, data => HasSmallIterationCount(data, 2) && Caltrop.DecryptWithPassword(data, "a long password 2026").Length == 8, rounds: 150);
    }

    [Fact]
    public void Encrypted_for_a_key_pair()
    {
        using var keyPair = CaltropKeyPair.Generate();
        string valid = Caltrop.Encrypt("a secret", keyPair.PublicKey);
        _fuzz.Text(valid, text => Caltrop.Decrypt(text, keyPair) == "a secret", rounds: 150);
    }

    [Fact]
    public void Tokens()
    {
        string valid = Caltrop.Tokens.Create("user 7", _key, TimeSpan.FromHours(1), purpose: "reset");
        _fuzz.Text(valid, text => Caltrop.Tokens.TryValidate(text, _key, out string? payload, purpose: "reset") && payload == "user 7");
        _fuzz.Text(valid, text => Caltrop.Tokens.Validate(text, _key, purpose: "reset") == "user 7", rounds: 100);
    }

    [Fact]
    public void Keys()
    {
        using var keyPair = CaltropKeyPair.Generate();
        _fuzz.Text(_key.Export(), text => CaltropKey.TryParse(text, out CaltropKey? key) && key.Matches(_key.IdBytes));
        _fuzz.Text(_key.Export(), text => CaltropKey.Parse(text) is not null, rounds: 100);
        _fuzz.Text(keyPair.ExportPrivateKey(), text => CaltropKeyPair.TryParse(text, out CaltropKeyPair? parsed) && parsed is not null);
        _fuzz.Text(keyPair.PublicKey.Export(), text => CaltropPublicKey.TryParse(text, out CaltropPublicKey? parsed) && parsed is not null);
        using var second = CaltropKey.Generate();
        _fuzz.Text($"{_key.Export()},{second.Export()}", text =>
        {
            CaltropKeyRing ring = CaltropKeyRing.Parse(text);
            return ring.Count == 2 && ring[0].Matches(_key.IdBytes) && ring[1].Matches(second.IdBytes);
        }, sameValue: _ => true, rounds: 150); // the separator may be a comma, semicolon or space
    }

    [Fact]
    public void Signatures()
    {
        using var keyPair = CaltropKeyPair.Generate();
        string valid = Caltrop.Sign("a message", keyPair);
        _fuzz.Text(valid, text => Caltrop.VerifySignature("a message", text, keyPair.PublicKey), rounds: 150);
    }

    [Fact]
    public void Seals()
    {
        string valid = Caltrop.Tamper.Seal("some settings", _key);
        _fuzz.Text(valid, text => Caltrop.Tamper.Check("some settings", text, _key));
    }

    [Fact]
    public void Api_keys()
    {
        string apiKey = Caltrop.ApiKeys.Generate("acme_live");
        string stored = Caltrop.ApiKeys.Hash(apiKey);
        _fuzz.Text(apiKey, text => Caltrop.ApiKeys.Verify(text, stored));
        _fuzz.Text(stored, text => Caltrop.ApiKeys.Verify(apiKey, text), sameValue: text => text.Equals(stored, StringComparison.OrdinalIgnoreCase)); // hex, in either case
        _fuzz.Text(apiKey, text => Caltrop.ApiKeys.IsWellFormed(text, "acme_live") && Caltrop.ApiKeys.Hash(text) == stored);
    }

    [Fact]
    public void Password_hashes()
    {
        string valid = Caltrop.Passwords.Hash("a long password 2026", iterations: 1000);
        _fuzz.Text(valid, text => HasSmallIterationCount(text) && Caltrop.Passwords.Verify("a long password 2026", text), rounds: 300);
        _fuzz.Survives(valid, text => Caltrop.Passwords.NeedsRehash(text));
    }

    [Fact]
    public void Webhook_signatures()
    {
        const string Secret = "whsec_a shared secret";
        string signature = Caltrop.Webhooks.Sign("{\"id\":1}", Secret);
        string mac = signature["sha256=".Length..];

        // Other services send hex in either case, with or without "sha256=", so those still count as the same.
        _fuzz.Text(signature, text => Caltrop.Webhooks.Verify("{\"id\":1}", text, Secret),
            sameValue: text => text.Trim().ToLowerInvariant() is { } lower && (lower == mac || lower == "sha256=" + mac));

        string timed = Caltrop.Webhooks.SignWithTimestamp("{\"id\":1}", Secret);
        string[] entries = timed.Split(',');
        _fuzz.Text(timed, text => Caltrop.Webhooks.VerifyWithTimestamp("{\"id\":1}", text, Secret),
            sameValue: text =>
            {
                string[] parts = text.Split(',', StringSplitOptions.TrimEntries);
                return parts.Count(part => part.StartsWith("t=", StringComparison.Ordinal)) == 1
                    && parts.Contains(entries[0])
                    && parts.Any(part => part.Equals(entries[1], StringComparison.OrdinalIgnoreCase));
            });
    }

    [Fact]
    public void Encrypted_streams()
    {
        byte[] plain = TestData.RandomBytes(150_000); // three chunks
        using var input = new MemoryStream(plain);
        using var encrypted = new MemoryStream();
        Caltrop.Files.Encrypt(input, encrypted, _key);
        _fuzz.Bytes(encrypted.ToArray(), data =>
        {
            using var output = new MemoryStream();
            Caltrop.Files.Decrypt(new MemoryStream(data), output, _key);
            return output.ToArray().AsSpan().SequenceEqual(plain);
        }, rounds: 150);
    }

    [Fact]
    public void Vault_files()
    {
        string path = _folder.File("fuzz.vault");
        using (var vault = CaltropVault.Create(path, _key))
        {
            vault.Set("a", "1");
            vault.Set("b", new byte[300]);
        }

        byte[] valid = File.ReadAllBytes(path);
        _fuzz.Bytes(valid, data =>
        {
            File.WriteAllBytes(path, data);
            using var vault = CaltropVault.Open(path, _key);
            return vault.Get("a") == "1";
        }, rounds: 150);
    }

    [Fact]
    public void Log_files()
    {
        string path = _folder.File("fuzz.log");
        using (var log = new CaltropLog(path, _key))
        {
            log.Write("one");
            log.Write("two\twith a tab");
            log.Write("three");
        }

        string valid = File.ReadAllText(path);
        string head;
        using (var log = new CaltropLog(path, _key))
        {
            head = log.Head;
        }

        // Windows line endings and a byte order mark (which text editors may add) are fine, and a last line with no
        // new line is still being written, so it is ignored.
        static string Settled(string text)
        {
            text = text.Replace("\r\n", "\n", StringComparison.Ordinal);
            text = text.StartsWith('\ufeff') ? text[1..] : text;
            return text[..(text.LastIndexOf('\n') + 1)];
        }

        _fuzz.Text(valid, text =>
        {
            File.WriteAllBytes(path, Encoding.UTF8.GetBytes(text));
            return CaltropLog.Verify(path, _key, head).IsIntact;
        }, sameValue: text => Settled(text) == valid, rounds: 300);
    }

    [Fact]
    public void Untrusted_text_never_breaks_the_helpers()
    {
        foreach (string text in _fuzz.RandomTexts(400))
        {
            Fuzzer.Expect(text, () =>
            {
                _ = Caltrop.Safe.FileName(text);
                _ = Caltrop.Safe.Html(text);
                _ = Caltrop.Safe.Mask(text);
                _ = Caltrop.Safe.CleanText(text);
                _ = Caltrop.Safe.IsSafeLink(text);
                _ = Caltrop.Decoys.Check(text);
                _ = Caltrop.ApiKeys.IsWellFormed(text);
                _ = Caltrop.Passwords.Check(text);
                if (text.Length > 0)
                {
                    _ = Caltrop.Safe.PathInside(_folder.Path, text);
                }

                return false;
            });
        }
    }

    [Fact]
    public void Untrusted_logins_never_break()
    {
        string stored = Caltrop.Passwords.Hash("a long password 2026", iterations: 1000);
        foreach (string text in _fuzz.RandomTexts(40))
        {
            Fuzzer.Expect(text, () => Caltrop.Passwords.Verify(text, stored));
            Fuzzer.Expect(text, () => Caltrop.Passwords.Create(text, text).Ok && false);
        }
    }

    /// <summary>Skips a damaged iteration count that would only make the test slow (up to 10 million is allowed).</summary>
    private static bool HasSmallIterationCount(byte[] data, int offset) =>
        data.Length < offset + 4 || BinaryPrimitives.ReadInt32BigEndian(data.AsSpan(offset)) is < 1 or <= 20_000 or > PasswordKdf.MaximumIterations;

    private static bool HasSmallIterationCount(string hash) =>
        !Caltrop.Passwords.TryParse(hash, out int iterations, out _, out _) || iterations <= 20_000;
}

/// <summary>The specific problems the fuzz tests found, so they stay fixed.</summary>
public sealed class StrictInputTests
{
    private readonly CaltropKey _key = CaltropKey.Generate();

    [Fact]
    public void Each_value_has_one_text_form()
    {
        string secret = Caltrop.Encrypt("x", _key);
        string token = Caltrop.Tokens.Create("user 7", _key, TimeSpan.FromHours(1));
        string exported = _key.Export();

        // Whitespace around a value is fine (it gets copied and pasted)...
        Assert.Equal("x", Caltrop.Decrypt($"  {secret}\n", _key));
        Assert.Equal("user 7", Caltrop.Tokens.Validate($"{token}\r\n", _key));
        Assert.True(CaltropKey.TryParse($" {exported} ", out _));

        // ...but nothing inside it, and no padding, though .NET itself would skip them.
        TestData.Throws(CaltropErrorCode.InvalidFormat, () => Caltrop.Decrypt(secret.Insert(10, "\n"), _key));
        TestData.Throws(CaltropErrorCode.InvalidFormat, () => Caltrop.Decrypt(secret + "==", _key));
        Assert.False(Caltrop.Tokens.TryValidate(token.Insert(8, " "), _key, out _));
        Assert.False(CaltropKey.TryParse(exported.Insert(4, " "), out _));
    }

    [Fact]
    public void A_password_with_broken_Unicode_is_just_wrong()
    {
        string stored = Caltrop.Passwords.Hash("a long password 2026", iterations: 1000);
        const string Broken = "a long password \ud800";

        Assert.False(Caltrop.Passwords.Verify(Broken, stored));
        CaltropNewPassword created = Caltrop.Passwords.Create(Broken + " with more words");
        Assert.False(created.Ok);
        Assert.Contains("cannot be used", created.Message, StringComparison.Ordinal);
        Assert.Throws<ArgumentException>(() => Caltrop.EncryptWithPassword("x", Broken));
        TestData.Throws(CaltropErrorCode.AuthenticationFailed, () => Caltrop.DecryptWithPassword(Caltrop.EncryptWithPassword("x", "a long password 2026"), Broken));
    }

    [Fact]
    public void An_api_key_with_broken_Unicode_is_just_wrong()
    {
        string apiKey = Caltrop.ApiKeys.Generate("acme_live");

        Assert.False(Caltrop.ApiKeys.Verify("acme_live_\ud800", Caltrop.ApiKeys.Hash(apiKey)));
        Assert.False(Caltrop.ApiKeys.IsWellFormed("acme_live_\ud800"));
    }

    [Fact]
    public void A_broken_password_never_matches_the_password_it_looks_like()
    {
        // .NET would turn half a surrogate pair into U+FFFD, so the two would hash the same.
        string stored = Caltrop.Passwords.Hash("a long password \ufffd", iterations: 1000);

        Assert.True(Caltrop.Passwords.Verify("a long password \ufffd", stored));
        Assert.False(Caltrop.Passwords.Verify("a long password \ud800", stored));
    }

    [Fact]
    public void Stored_password_hashes_have_one_spelling()
    {
        string stored = Caltrop.Passwords.Hash("a long password 2026", iterations: 1000);
        string[] parts = stored.Split('$');
        const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        string salt = parts[3];
        string otherSpelling = salt[..^1] + Alphabet[Alphabet.IndexOf(salt[^1], StringComparison.Ordinal) ^ 1]; // the same 16 bytes to .NET

        foreach (string changed in new[]
        {
            stored + "=",                                   // the PHC format has no padding
            stored.Replace(salt, salt + "==", StringComparison.Ordinal),
            stored.Replace("$i=1000$", "$i=01000$", StringComparison.Ordinal),
            stored.Replace("$i=1000$", "$i=1000\0$", StringComparison.Ordinal), // .NET's number parsing skips a trailing \0
            stored.Replace(salt, otherSpelling, StringComparison.Ordinal),
            stored.Replace(salt, salt.Insert(5, " "), StringComparison.Ordinal),
        })
        {
            TestData.Throws(CaltropErrorCode.InvalidFormat, () => Caltrop.Passwords.Verify("a long password 2026", changed));
        }
    }

    [Fact]
    public void Text_with_noncharacters_is_cleaned_not_refused()
    {
        // U+FFFE and U+FFFF are valid UTF-16 that no text should contain, and .NET refuses to normalize them.
        Assert.Equal("ab", Caltrop.Safe.CleanText("a\ufffeb\uffff"));
        Assert.Equal("report.pdf", Caltrop.Safe.FileName("report\ufffe.pdf"));
        Assert.False(Caltrop.Passwords.Check("\ufffe\ufeff short").Ok);
    }

    [Fact]
    public void Stored_password_hashes_must_be_whole()
    {
        string stored = Caltrop.Passwords.Hash("a long password 2026", iterations: 1000);
        string cutDown = stored[..^21]; // still valid Base64, but only 16 of its 32 bytes

        TestData.Throws(CaltropErrorCode.InvalidFormat, () => Caltrop.Passwords.Verify("a long password 2026", cutDown));
    }
}

/// <summary>Makes damaged copies of valid data, with a fixed seed so any failure can be repeated.</summary>
internal sealed class Fuzzer(int seed, int scale = 1)
{
    /// <summary>Characters that mean something in Caltrop's formats.</summary>
    private const string FormatChars = "-_=+/ \t\n$:.,0123456789abcdefABCDEF";

    /// <summary>An accent, a combining accent, invisible characters, a right-to-left mark and both halves of an emoji.</summary>
    private const string UnicodeChars = "\u00e9\u0301\u200b\ufeff\u202e\ud83d\ude00";

    private readonly System.Random _random = new(seed);

    /// <summary>Checks <paramref name="accepts"/> against damaged copies of <paramref name="valid"/>.</summary>
    /// <param name="valid">A valid value.</param>
    /// <param name="accepts">Reads a value and says whether it was accepted as the original.</param>
    /// <param name="sameValue">Says whether a damaged copy still means exactly the same; by default, only extra whitespace around it.</param>
    /// <param name="rounds">How many random changes to try, on top of every cut-off length.</param>
    public void Text(string valid, Func<string, bool> accepts, Func<string, bool>? sameValue = null, int rounds = 1000)
    {
        Assert.True(accepts(valid), "The valid value itself was not accepted.");
        sameValue ??= text => text.Trim() == valid;
        foreach (string text in TextMutations(valid, rounds * scale))
        {
            if (Expect(text, () => accepts(text)) && !sameValue(text))
            {
                Assert.Fail($"A changed value was accepted: {Show(text)} (the original was {Show(valid)})");
            }
        }
    }

    /// <summary>Checks that <paramref name="read"/> only ever answers, or throws a <see cref="CaltropException"/>, for damaged copies of <paramref name="valid"/>.</summary>
    public void Survives(string valid, Func<string, bool> read, int rounds = 1000)
    {
        foreach (string text in TextMutations(valid, rounds * scale))
        {
            Expect(text, () => read(text));
        }
    }

    /// <summary>Checks <paramref name="accepts"/> against damaged copies of <paramref name="valid"/>.</summary>
    public void Bytes(byte[] valid, Func<byte[], bool> accepts, int rounds = 1000)
    {
        Assert.True(accepts(valid), "The valid value itself was not accepted.");
        foreach (byte[] data in ByteMutations(valid, rounds * scale))
        {
            if (Expect(Convert.ToHexString(data.AsSpan(0, Math.Min(data.Length, 64))), () => accepts(data)) && !data.AsSpan().SequenceEqual(valid))
            {
                Assert.Fail($"Changed data was accepted: {Convert.ToHexString(data)}");
            }
        }
    }

    /// <summary>Runs <paramref name="read"/>: a <see cref="CaltropException"/> counts as "no", any other exception fails the test.</summary>
    public static bool Expect(string input, Func<bool> read)
    {
        try
        {
            return read();
        }
        catch (CaltropException)
        {
            return false;
        }
        catch (ArgumentException ex) when (input.Length == 0)
        {
            _ = ex; // an empty value may be refused as an argument
            return false;
        }
        catch (Exception ex)
        {
            Assert.Fail($"{ex.GetType().Name} for {Show(input)}: {ex.Message}\n{ex.StackTrace}");
            return false;
        }
    }

    public IEnumerable<string> RandomTexts(int count)
    {
        yield return "";
        yield return " ";
        yield return "\0";
        yield return "\ud800";            // half a surrogate pair
        yield return "a\udc00b";
        yield return new string('a', 70_000);
        yield return "../../" + new string('x', 300);
        for (int i = 0; i < count * scale; i++)
        {
            yield return RandomText(_random.Next(0, 60));
        }
    }

    private IEnumerable<string> TextMutations(string valid, int rounds)
    {
        yield return "";
        yield return " ";
        yield return valid + valid;
        yield return valid.ToUpperInvariant();
        yield return valid.ToLowerInvariant();
        for (int length = 0; length < valid.Length; length += Math.Max(1, valid.Length / 50))
        {
            yield return valid[..length];
        }

        for (int round = 0; round < rounds; round++)
        {
            char[] chars = valid.ToCharArray();
            int at = _random.Next(chars.Length);
            switch (_random.Next(9))
            {
                case 0:
                    chars[at] = RandomChar();
                    yield return new string(chars);
                    break;
                case 1:
                    yield return valid.Insert(_random.Next(valid.Length + 1), RandomChar().ToString());
                    break;
                case 2:
                    yield return valid.Remove(at, 1);
                    break;
                case 3:
                    int next = Math.Min(at + 1, chars.Length - 1);
                    (chars[at], chars[next]) = (chars[next], chars[at]);
                    yield return new string(chars);
                    break;
                case 4:
                    yield return valid + RandomText(_random.Next(1, 20));
                    break;
                case 5:
                    yield return RandomText(_random.Next(0, valid.Length * 2));
                    break;
                case 6:
                    yield return valid[.._random.Next(valid.Length)] + RandomText(_random.Next(1, 10));
                    break;
                case 7:
                    yield return valid.Insert(_random.Next(valid.Length + 1), " \t\n="[_random.Next(4)].ToString()); // whitespace or padding inside
                    break;
                default:
                    chars[at] = (char)(chars[at] ^ (1 << _random.Next(7)));
                    yield return new string(chars);
                    break;
            }
        }
    }

    private IEnumerable<byte[]> ByteMutations(byte[] valid, int rounds)
    {
        yield return [];
        yield return [.. valid, .. valid];
        for (int length = 0; length < valid.Length; length += Math.Max(1, valid.Length / 50))
        {
            yield return valid[..length];
        }

        for (int round = 0; round < rounds; round++)
        {
            byte[] copy = (byte[])valid.Clone();
            int at = _random.Next(copy.Length);
            switch (_random.Next(6))
            {
                case 0:
                    copy[at] ^= (byte)(1 << _random.Next(8));
                    yield return copy;
                    break;
                case 1:
                    copy[at] = (byte)_random.Next(256);
                    yield return copy;
                    break;
                case 2:
                    yield return [.. valid, .. RandomBytes(_random.Next(1, 40))];
                    break;
                case 3:
                    yield return RandomBytes(_random.Next(0, Math.Min(valid.Length * 2, 4096)));
                    break;
                case 4:
                    copy.AsSpan(at, Math.Min(4, copy.Length - at)).Fill(0xFF); // huge numbers in length fields
                    yield return copy;
                    break;
                default:
                    copy.AsSpan(at, Math.Min(4, copy.Length - at)).Clear();
                    yield return copy;
                    break;
            }
        }
    }

    private string RandomText(int length)
    {
        var builder = new StringBuilder(length);
        for (int i = 0; i < length; i++)
        {
            builder.Append(RandomChar());
        }

        return builder.ToString();
    }

    private char RandomChar() => _random.Next(5) switch
    {
        0 => (char)_random.Next(32, 127),
        1 => FormatChars[_random.Next(FormatChars.Length)],
        2 => (char)_random.Next(0, 32),
        3 => UnicodeChars[_random.Next(UnicodeChars.Length)],
        _ => (char)_random.Next(0x80, 0x10000),
    };

    private byte[] RandomBytes(int length)
    {
        byte[] bytes = new byte[length];
        _random.NextBytes(bytes);
        return bytes;
    }

    private static string Show(string text) =>
        text.Length > 120 ? $"\"{Escape(text[..120])}...\" ({text.Length} characters)" : $"\"{Escape(text)}\"";

    private static string Escape(string text)
    {
        var builder = new StringBuilder();
        foreach (char c in text)
        {
            builder.Append(c is < ' ' or > '~' ? $"\\u{(int)c:x4}" : c.ToString());
        }

        return builder.ToString();
    }
}
