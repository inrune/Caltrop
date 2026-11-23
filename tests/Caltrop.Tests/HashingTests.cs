using System.Text;

namespace CaltropSecurity.Tests;

public class HashingTests
{
    private const string Sha256OfAbc = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    [Fact]
    public void Sha256_matches_the_standard_test_vectors()
    {
        Assert.Equal(Sha256OfAbc, Caltrop.Hashing.Sha256("abc"));
        Assert.Equal(Sha256OfAbc, Caltrop.Hashing.Sha256("abc"u8.ToArray()));
        Assert.Equal(Sha256OfAbc, Caltrop.Hashing.Sha256(new MemoryStream("abc"u8.ToArray())));
        Assert.Equal("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", Caltrop.Hashing.Sha256(""));
    }

    [Fact]
    public void Sha256File_hashes_the_file_contents()
    {
        string path = Path.GetTempFileName();
        try
        {
            File.WriteAllText(path, "abc");
            Assert.Equal(Sha256OfAbc, Caltrop.Hashing.Sha256File(path));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Sha512_matches_the_standard_test_vector()
    {
        const string expected = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";

        Assert.Equal(expected, Caltrop.Hashing.Sha512("abc"));
        Assert.Equal(expected, Caltrop.Hashing.Sha512("abc"u8.ToArray()));
    }

    [Fact]
    public void HmacSha256_matches_RFC_4231()
    {
        const string expected = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";

        Assert.Equal(expected, Caltrop.Hashing.HmacSha256("what do ya want for nothing?", "Jefe"));
        Assert.Equal(expected, Caltrop.Hashing.HmacSha256(Encoding.ASCII.GetBytes("what do ya want for nothing?"), Encoding.ASCII.GetBytes("Jefe")));
    }

    [Fact]
    public void BlindIndex_is_deterministic_and_keyed()
    {
        using var key = CaltropKey.Generate();
        using var otherKey = CaltropKey.Generate();

        string index = Caltrop.Hashing.BlindIndex("alice@example.com", key, "users.email");

        Assert.Matches("^[0-9a-f]{64}$", index);
        Assert.Equal(index, Caltrop.Hashing.BlindIndex("alice@example.com", key, "users.email"));
        Assert.NotEqual(index, Caltrop.Hashing.BlindIndex("bob@example.com", key, "users.email"));
        Assert.NotEqual(index, Caltrop.Hashing.BlindIndex("alice@example.com", key, "users.backup_email"));
        Assert.NotEqual(index, Caltrop.Hashing.BlindIndex("alice@example.com", key));
        Assert.NotEqual(index, Caltrop.Hashing.BlindIndex("alice@example.com", otherKey, "users.email"));
        Assert.NotEqual(Caltrop.Hashing.Sha256("alice@example.com"), index);
    }

    [Fact]
    public void BlindIndex_survives_a_key_export_and_import()
    {
        using var key = CaltropKey.Generate();
        using var reloaded = CaltropKey.Parse(key.Export());

        Assert.Equal(Caltrop.Hashing.BlindIndex("x", key), Caltrop.Hashing.BlindIndex("x", reloaded));
    }
}
