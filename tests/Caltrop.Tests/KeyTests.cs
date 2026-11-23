namespace CaltropSecurity.Tests;

public class KeyTests
{
    [Fact]
    public void Export_then_Parse_gives_the_same_key()
    {
        using var key = CaltropKey.Generate();
        string text = key.Export();

        using var parsed = CaltropKey.Parse(text);

        Assert.StartsWith("ctk_", text);
        Assert.Equal(52, text.Length);
        Assert.Equal(key.ToBytes(), parsed.ToBytes());
        Assert.Equal(key.Id, parsed.Id);
    }

    [Fact]
    public void Generated_keys_are_different()
    {
        using var a = CaltropKey.Generate();
        using var b = CaltropKey.Generate();

        Assert.NotEqual(a.ToBytes(), b.ToBytes());
        Assert.NotEqual(a.Id, b.Id);
    }

    [Fact]
    public void Id_is_eight_hex_characters_and_depends_only_on_the_key()
    {
        byte[] material = TestData.RandomBytes(32);
        using var a = CaltropKey.FromBytes(material);
        using var b = CaltropKey.FromBytes(material);

        Assert.Matches("^[0-9a-f]{8}$", a.Id);
        Assert.Equal(a.Id, b.Id);
    }

    [Fact]
    public void A_changed_character_is_caught_by_the_checksum()
    {
        using var key = CaltropKey.Generate();
        char[] text = key.Export().ToCharArray();
        text[10] = text[10] == 'A' ? 'B' : 'A';

        CaltropException ex = TestData.Throws(CaltropErrorCode.InvalidKey, () => CaltropKey.Parse(new string(text)));
        Assert.Contains("checksum", ex.Message);
    }

    [Fact]
    public void A_truncated_key_is_rejected()
    {
        using var key = CaltropKey.Generate();
        string text = key.Export();

        TestData.Throws(CaltropErrorCode.InvalidKey, () => CaltropKey.Parse(text[..^1]));
        TestData.Throws(CaltropErrorCode.InvalidKey, () => CaltropKey.Parse("ctk_"));
    }

    [Fact]
    public void Surrounding_whitespace_is_ignored()
    {
        using var key = CaltropKey.Generate();

        using var parsed = CaltropKey.Parse($"  {key.Export()}\n");

        Assert.Equal(key.Id, parsed.Id);
    }

    [Fact]
    public void Raw_32_byte_keys_in_common_text_formats_are_accepted()
    {
        byte[] material = TestData.RandomBytes(32);
        using var expected = CaltropKey.FromBytes(material);
        string base64 = Convert.ToBase64String(material);
        string[] forms =
        [
            base64,                                                   // openssl rand -base64 32
            base64.TrimEnd('='),                                      // Base64 without padding
            base64.TrimEnd('=').Replace('+', '-').Replace('/', '_'),  // Base64Url
            Convert.ToHexString(material),                            // openssl rand -hex 32 (upper case)
            Convert.ToHexStringLower(material),                       // hex, lower case
        ];

        foreach (string form in forms)
        {
            using var parsed = CaltropKey.Parse(form);
            Assert.Equal(expected.Id, parsed.Id);
        }
    }

    [Theory]
    [InlineData("")]
    [InlineData("not a key")]
    [InlineData("ctpub_abc")]
    [InlineData("c2hvcnQ=")]
    public void Invalid_key_text_is_rejected(string text)
    {
        TestData.Throws(CaltropErrorCode.InvalidKey, () => CaltropKey.Parse(text));
        Assert.False(CaltropKey.TryParse(text, out _));
    }

    [Fact]
    public void TryParse_returns_the_key_or_false()
    {
        using var key = CaltropKey.Generate();

        Assert.True(CaltropKey.TryParse(key.Export(), out CaltropKey? parsed));
        Assert.Equal(key.Id, parsed.Id);
        Assert.False(CaltropKey.TryParse(null, out CaltropKey? missing));
        Assert.Null(missing);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(16)]
    [InlineData(31)]
    [InlineData(33)]
    public void FromBytes_requires_exactly_32_bytes(int length)
    {
        Assert.Throws<ArgumentException>(() => CaltropKey.FromBytes(new byte[length]));
    }

    [Fact]
    public void ToString_never_contains_the_key()
    {
        using var key = CaltropKey.Generate();

        Assert.Equal($"CaltropKey({key.Id})", key.ToString());
        Assert.DoesNotContain(key.Export()[4..20], key.ToString());
    }

    [Fact]
    public void ToBytes_returns_a_copy()
    {
        using var key = CaltropKey.Generate();
        byte[] copy = key.ToBytes();
        copy[0] ^= 0xFF;

        Assert.NotEqual(copy, key.ToBytes());
    }

    [Fact]
    public void A_disposed_key_cannot_be_used()
    {
        var key = CaltropKey.Generate();
        key.Dispose();

        Assert.Throws<ObjectDisposedException>(() => key.Export());
        Assert.Throws<ObjectDisposedException>(() => Caltrop.Encrypt("x", key));
        Assert.Throws<ObjectDisposedException>(() => Caltrop.Tokens.Create("x", key, TimeSpan.FromMinutes(1)));
    }

    [Fact]
    public void KeyRing_Parse_reads_keys_newest_first()
    {
        using var newest = CaltropKey.Generate();
        using var older = CaltropKey.Generate();
        using var oldest = CaltropKey.Generate();

        var ring = CaltropKeyRing.Parse($"{newest.Export()}, {older.Export()};\n{oldest.Export()}");

        Assert.Equal(3, ring.Count);
        Assert.Equal(newest.Id, ring.Primary.Id);
        Assert.Equal(older.Id, ring[1].Id);
        Assert.Equal(oldest.Id, ring[2].Id);
    }

    [Theory]
    [InlineData("")]
    [InlineData(" , ; ")]
    public void KeyRing_Parse_rejects_empty_text(string text)
    {
        TestData.Throws(CaltropErrorCode.InvalidKey, () => CaltropKeyRing.Parse(text));
    }

    [Fact]
    public void KeyRing_ToString_lists_ids_only()
    {
        using var key = CaltropKey.Generate();
        var ring = new CaltropKeyRing(key);

        Assert.Contains(key.Id, ring.ToString());
        Assert.DoesNotContain(key.Export()[4..20], ring.ToString());
    }

    [Fact]
    public void KeyRing_rejects_null_keys()
    {
        using var key = CaltropKey.Generate();

        Assert.Throws<ArgumentNullException>(() => new CaltropKeyRing(null!));
        Assert.Throws<ArgumentNullException>(() => new CaltropKeyRing(key, null!));
    }
}
