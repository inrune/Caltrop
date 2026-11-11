using CaltropSecurity.Internal;

namespace CaltropSecurity.Tests;

public sealed class FileTests : IDisposable
{
    private const int Chunk = ChunkCipher.ChunkSize;
    private static readonly CaltropKey s_key = CaltropKey.Generate();
    private readonly string _directory = Directory.CreateTempSubdirectory("caltrop-tests-").FullName;

    public void Dispose() => Directory.Delete(_directory, recursive: true);

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(100)]
    [InlineData(Chunk - 1)]
    [InlineData(Chunk)]
    [InlineData(Chunk + 1)]
    [InlineData((3 * Chunk) + 17)]
    public void Streams_round_trip(int size)
    {
        byte[] data = TestData.RandomBytes(size);

        byte[] encrypted = EncryptStream(data, s_key);

        Assert.Equal(30 + size + (16 * ((size / Chunk) + 1)), encrypted.Length);
        Assert.Equal(data, DecryptStream(encrypted, s_key));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(Chunk - 1)]
    [InlineData(Chunk)]
    [InlineData(Chunk + 1)]
    [InlineData((3 * Chunk) + 17)]
    public async Task Streams_round_trip_asynchronously(int size)
    {
        byte[] data = TestData.RandomBytes(size);
        var encrypted = new MemoryStream();
        var decrypted = new MemoryStream();

        await Caltrop.Files.EncryptAsync(new MemoryStream(data), encrypted, s_key, TestContext.Current.CancellationToken);
        encrypted.Position = 0;
        await Caltrop.Files.DecryptAsync(encrypted, decrypted, s_key, TestContext.Current.CancellationToken);

        Assert.Equal(data, decrypted.ToArray());
    }

    [Fact]
    public async Task Sync_and_async_formats_are_the_same()
    {
        byte[] data = TestData.RandomBytes(Chunk + 5);
        var encrypted = new MemoryStream();
        await Caltrop.Files.EncryptAsync(new MemoryStream(data), encrypted, s_key, TestContext.Current.CancellationToken);

        Assert.Equal(data, DecryptStream(encrypted.ToArray(), s_key));
    }

    [Fact]
    public void Cutting_off_the_end_is_detected_even_at_a_chunk_boundary()
    {
        byte[] encrypted = EncryptStream(TestData.RandomBytes((2 * Chunk) + 100), s_key);
        int[] cuts = [0, 1, 2, 29, 30, 31, 46, 30 + Chunk + 15, 30 + Chunk + 16, 30 + Chunk + 17, 30 + (2 * (Chunk + 16)), encrypted.Length - 1];

        foreach (int cut in cuts)
        {
            Assert.Throws<CaltropException>(() => DecryptStream(encrypted[..cut], s_key));
        }
    }

    [Theory]
    [InlineData(10, 1)]
    [InlineData(10, Chunk + 100)]
    [InlineData(Chunk, 1)]
    public void Extra_data_after_the_end_is_detected(int size, int extra)
    {
        byte[] encrypted = EncryptStream(TestData.RandomBytes(size), s_key);

        TestData.Throws(CaltropErrorCode.AuthenticationFailed, () => DecryptStream([.. encrypted, .. new byte[extra]], s_key));
    }

    [Fact]
    public void Swapping_chunks_is_detected()
    {
        byte[] encrypted = EncryptStream(TestData.RandomBytes((3 * Chunk) + 1), s_key);
        const int sealedChunk = Chunk + 16;
        byte[] swapped = (byte[])encrypted.Clone();
        encrypted.AsSpan(30, sealedChunk).CopyTo(swapped.AsSpan(30 + sealedChunk));
        encrypted.AsSpan(30 + sealedChunk, sealedChunk).CopyTo(swapped.AsSpan(30));

        TestData.Throws(CaltropErrorCode.AuthenticationFailed, () => DecryptStream(swapped, s_key));
    }

    [Fact]
    public void Changed_bytes_are_detected()
    {
        byte[] encrypted = EncryptStream(TestData.RandomBytes(Chunk + 10), s_key);

        foreach (int i in new[] { 2, 6, 29, 30, 1000, 30 + Chunk + 16, encrypted.Length - 1 })
        {
            byte[] tampered = TestData.FlipBit(encrypted, i);
            Assert.Throws<CaltropException>(() => DecryptStream(tampered, s_key));
        }
    }

    [Fact]
    public void A_different_key_is_reported_as_a_key_mismatch()
    {
        using var other = CaltropKey.Generate();
        byte[] encrypted = EncryptStream([1, 2, 3], s_key);

        TestData.Throws(CaltropErrorCode.KeyMismatch, () => DecryptStream(encrypted, other));
    }

    [Fact]
    public void A_key_ring_decrypts_streams_from_older_keys()
    {
        using var oldKey = CaltropKey.Generate();
        byte[] data = TestData.RandomBytes(500);
        byte[] encrypted = EncryptStream(data, oldKey);
        var output = new MemoryStream();

        Caltrop.Files.Decrypt(new MemoryStream(encrypted), output, new CaltropKeyRing(s_key, oldKey));

        Assert.Equal(data, output.ToArray());
    }

    [Fact]
    public async Task Password_streams_round_trip()
    {
        byte[] data = TestData.RandomBytes(Chunk + 3);
        var encrypted = new MemoryStream();
        var decrypted = new MemoryStream();

        Caltrop.Files.EncryptWithPassword(new MemoryStream(data), encrypted, "pw");
        encrypted.Position = 0;
        await Caltrop.Files.DecryptWithPasswordAsync(encrypted, decrypted, "pw", TestContext.Current.CancellationToken);

        Assert.Equal(data, decrypted.ToArray());
        Assert.Equal(0x06, encrypted.ToArray()[1]);
    }

    [Fact]
    public void A_wrong_password_fails()
    {
        var encrypted = new MemoryStream();
        Caltrop.Files.EncryptWithPassword(new MemoryStream([1, 2, 3]), encrypted, "right");
        encrypted.Position = 0;

        TestData.Throws(CaltropErrorCode.AuthenticationFailed, () => Caltrop.Files.DecryptWithPassword(encrypted, new MemoryStream(), "wrong"));
    }

    [Fact]
    public void The_wrong_kind_of_stream_gets_a_helpful_error()
    {
        byte[] encrypted = EncryptStream([1, 2, 3], s_key);

        CaltropException ex = TestData.Throws(CaltropErrorCode.WrongDataType, () => Caltrop.Files.DecryptWithPassword(new MemoryStream(encrypted), new MemoryStream(), "pw"));
        Assert.Contains("Caltrop.Files.Decrypt", ex.Message);
    }

    [Fact]
    public void Empty_input_is_reported_clearly()
    {
        CaltropException ex = TestData.Throws(CaltropErrorCode.InvalidFormat, () => DecryptStream([], s_key));
        Assert.Contains("empty", ex.Message);
    }

    [Fact]
    public void Streams_are_left_open()
    {
        var input = new MemoryStream([1, 2, 3]);
        var output = new MemoryStream();

        Caltrop.Files.Encrypt(input, output, s_key);

        Assert.True(input.CanRead);
        Assert.True(output.CanWrite);
    }

    [Fact]
    public void Files_round_trip()
    {
        byte[] data = TestData.RandomBytes((2 * Chunk) + 7);
        string plain = Path.Combine(_directory, "report.pdf");
        string encrypted = plain + ".caltrop";
        string restored = Path.Combine(_directory, "restored.pdf");
        File.WriteAllBytes(plain, data);

        Caltrop.Files.EncryptFile(plain, encrypted, s_key);
        Caltrop.Files.DecryptFile(encrypted, restored, s_key);

        Assert.Equal(data, File.ReadAllBytes(restored));
        Assert.NotEqual(data, File.ReadAllBytes(encrypted)[30..(30 + data.Length)]);
        Assert.Equal(3, Directory.GetFiles(_directory).Length); // no temporary files left behind
    }

    [Fact]
    public async Task Files_round_trip_asynchronously()
    {
        byte[] data = TestData.RandomBytes(Chunk + 1);
        string plain = Path.Combine(_directory, "a.bin");
        string encrypted = Path.Combine(_directory, "a.bin.caltrop");
        string restored = Path.Combine(_directory, "b.bin");
        await File.WriteAllBytesAsync(plain, data, TestContext.Current.CancellationToken);

        await Caltrop.Files.EncryptFileAsync(plain, encrypted, s_key, TestContext.Current.CancellationToken);
        await Caltrop.Files.DecryptFileAsync(encrypted, restored, s_key, TestContext.Current.CancellationToken);

        Assert.Equal(data, await File.ReadAllBytesAsync(restored, TestContext.Current.CancellationToken));
    }

    [Fact]
    public void A_file_can_be_encrypted_and_decrypted_in_place()
    {
        byte[] data = TestData.RandomBytes(1000);
        string path = Path.Combine(_directory, "in-place.txt");
        File.WriteAllBytes(path, data);

        Caltrop.Files.EncryptFile(path, path, s_key);
        Assert.NotEqual(data.Length, new FileInfo(path).Length);
        Caltrop.Files.DecryptFile(path, path, s_key);

        Assert.Equal(data, File.ReadAllBytes(path));
    }

    [Fact]
    public void A_failed_decryption_leaves_no_output_file()
    {
        string plain = Path.Combine(_directory, "data.bin");
        string encrypted = Path.Combine(_directory, "data.bin.caltrop");
        string output = Path.Combine(_directory, "never.bin");
        File.WriteAllBytes(plain, TestData.RandomBytes((3 * Chunk) + 1));
        Caltrop.Files.EncryptFile(plain, encrypted, s_key);
        byte[] tampered = File.ReadAllBytes(encrypted);
        tampered[^1] ^= 1; // the damage is only found at the very end
        File.WriteAllBytes(encrypted, tampered);

        Assert.Throws<CaltropException>(() => Caltrop.Files.DecryptFile(encrypted, output, s_key));

        Assert.False(File.Exists(output));
        Assert.Equal(2, Directory.GetFiles(_directory).Length);
    }

    [Fact]
    public void A_failed_decryption_keeps_the_existing_output_file()
    {
        string encrypted = Path.Combine(_directory, "bad.caltrop");
        string output = Path.Combine(_directory, "existing.txt");
        File.WriteAllBytes(encrypted, EncryptStream([1, 2, 3], s_key)[..^1]);
        File.WriteAllText(output, "keep me");

        Assert.Throws<CaltropException>(() => Caltrop.Files.DecryptFile(encrypted, output, s_key));

        Assert.Equal("keep me", File.ReadAllText(output));
    }

    [Fact]
    public void Decrypted_files_are_private_on_unix()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        string plain = Path.Combine(_directory, "p.txt");
        string encrypted = Path.Combine(_directory, "p.caltrop");
        string restored = Path.Combine(_directory, "r.txt");
        File.WriteAllText(plain, "private");
        Caltrop.Files.EncryptFileWithPassword(plain, encrypted, "pw");

        Caltrop.Files.DecryptFileWithPassword(encrypted, restored, "pw");

        Assert.Equal("private", File.ReadAllText(restored));
        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(restored));
    }

    [Fact]
    public void Unusable_streams_are_rejected()
    {
        var closed = new MemoryStream();
        closed.Dispose();

        Assert.Throws<ArgumentException>(() => Caltrop.Files.Encrypt(closed, new MemoryStream(), s_key));
        Assert.Throws<ArgumentException>(() => Caltrop.Files.Encrypt(new MemoryStream(), new MemoryStream([], writable: false), s_key));
    }

    private static byte[] EncryptStream(byte[] data, CaltropKey key)
    {
        var output = new MemoryStream();
        Caltrop.Files.Encrypt(new MemoryStream(data), output, key);
        return output.ToArray();
    }

    private static byte[] DecryptStream(byte[] data, CaltropKey key)
    {
        var output = new MemoryStream();
        Caltrop.Files.Decrypt(new MemoryStream(data), output, key);
        return output.ToArray();
    }
}
