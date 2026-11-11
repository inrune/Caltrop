using System.Buffers.Binary;
using System.Security.Cryptography;

namespace CaltropSecurity.Internal;

/// <summary>
/// Chunked authenticated encryption for streams (the STREAM construction). The data is split into 64 KiB chunks;
/// each is sealed with AES-256-GCM under a per-file key, using the chunk number and a "last chunk" flag as the
/// nonce. Reordering, dropping, truncating or appending chunks is detected.
/// </summary>
internal sealed class ChunkCipher : IDisposable
{
    public const int ChunkSize = 64 * 1024;
    public const int SealedChunkSize = ChunkSize + Format.TagSize;

    private readonly AesGcm _aes;
    private readonly byte[] _header;
    private readonly byte[] _nonce = new byte[Format.GcmNonceSize];
    private long _counter;

    public ChunkCipher(ReadOnlySpan<byte> fileKey, byte[] header)
    {
        _aes = new AesGcm(fileKey, Format.TagSize);
        _header = header;
    }

    /// <summary>Seals one chunk; <paramref name="destination"/> receives ciphertext followed by the tag.</summary>
    public void Seal(ReadOnlySpan<byte> plaintext, Span<byte> destination, bool last)
    {
        SetNonce(last);
        _aes.Encrypt(_nonce, plaintext, destination[..plaintext.Length], destination.Slice(plaintext.Length, Format.TagSize), _header);
        _counter++;
    }

    public bool TryOpen(ReadOnlySpan<byte> sealedChunk, Span<byte> plaintext, bool last)
    {
        SetNonce(last);
        try
        {
            _aes.Decrypt(_nonce, sealedChunk[..^Format.TagSize], sealedChunk[^Format.TagSize..], plaintext[..(sealedChunk.Length - Format.TagSize)], _header);
        }
        catch (AuthenticationTagMismatchException)
        {
            return false;
        }

        _counter++;
        return true;
    }

    public void Dispose() => _aes.Dispose();

    private void SetNonce(bool last)
    {
        // 3 zero bytes || 64-bit chunk counter || last-chunk flag
        _nonce.AsSpan(0, 3).Clear();
        BinaryPrimitives.WriteInt64BigEndian(_nonce.AsSpan(3), _counter);
        _nonce[11] = last ? (byte)1 : (byte)0;
    }
}

/// <summary>Stream headers and key derivation for <see cref="Caltrop.Files"/>.</summary>
internal static class StreamHeaders
{
    // Secret key: version(1) kind(1) keyId(4) nonce(24)
    public const int KeyHeaderSize = 2 + Format.KeyIdSize + Format.MessageNonceSize;

    // Password: version(1) kind(1) iterations(4) salt(16)
    public const int PasswordHeaderSize = 2 + 4 + PasswordKdf.SaltSize;

    public static byte[] NewKeyHeader(CaltropKey key, out byte[] fileKey)
    {
        ArgumentNullException.ThrowIfNull(key);
        key.ThrowIfDisposed();
        Aead.EnsureSupported();
        byte[] header = new byte[KeyHeaderSize];
        header[0] = Format.Version;
        header[1] = (byte)BlobKind.SecretKeyStream;
        key.IdBytes.CopyTo(header.AsSpan(2));
        RandomNumberGenerator.Fill(header.AsSpan(2 + Format.KeyIdSize));
        fileKey = DeriveFileKey(key, header);
        return header;
    }

    public static byte[] NewPasswordHeader(string password, out byte[] fileKey)
    {
        PasswordKdf.ValidateNewPassword(password, nameof(password));
        Aead.EnsureSupported();
        byte[] header = new byte[PasswordHeaderSize];
        header[0] = Format.Version;
        header[1] = (byte)BlobKind.PasswordStream;
        BinaryPrimitives.WriteInt32BigEndian(header.AsSpan(2), PasswordKdf.DefaultIterations);
        RandomNumberGenerator.Fill(header.AsSpan(6));
        fileKey = new byte[Format.KeySize];
        PasswordKdf.Derive(password, header.AsSpan(6), PasswordKdf.DefaultIterations, fileKey);
        return header;
    }

    /// <summary>Returns one candidate file key per key whose id matches the header.</summary>
    public static List<byte[]> KeyCandidates(byte[] header, IReadOnlyList<CaltropKey> keys)
    {
        ReadOnlySpan<byte> keyId = header.AsSpan(2, Format.KeyIdSize);
        var candidates = new List<byte[]>(1);
        foreach (CaltropKey key in keys)
        {
            if (key.Matches(keyId))
            {
                candidates.Add(DeriveFileKey(key, header));
            }
        }

        return candidates.Count > 0 ? candidates : throw Errors.KeyMismatch(keyId, keys.Count);
    }

    public static List<byte[]> PasswordCandidate(byte[] header, string password)
    {
        int iterations = BinaryPrimitives.ReadInt32BigEndian(header.AsSpan(2));
        if (iterations is < 1 or > PasswordKdf.MaximumIterations)
        {
            throw Errors.InvalidFormat("the password iteration count in its header is out of range.");
        }

        byte[] fileKey = new byte[Format.KeySize];
        PasswordKdf.Derive(password, header.AsSpan(6, PasswordKdf.SaltSize), iterations, fileKey);
        return [fileKey];
    }

    private static byte[] DeriveFileKey(CaltropKey key, byte[] header)
    {
        byte[] fileKey = new byte[Format.KeySize];
        key.Derive(Labels.Stream, header.AsSpan(2 + Format.KeyIdSize, Format.MessageNonceSize), fileKey);
        return fileKey;
    }
}

/// <summary>The read/write loops, in synchronous and asynchronous form.</summary>
internal static class StreamCrypto
{
    public static void Encrypt(Stream input, Stream output, byte[] header, byte[] fileKey)
    {
        byte[] plain = new byte[ChunkCipher.ChunkSize];
        byte[] box = new byte[ChunkCipher.SealedChunkSize];
        try
        {
            using var cipher = new ChunkCipher(fileKey, header);
            output.Write(header);
            while (true)
            {
                int read = input.ReadAtLeast(plain, plain.Length, throwOnEndOfStream: false);
                bool last = read < plain.Length;
                cipher.Seal(plain.AsSpan(0, read), box, last);
                output.Write(box, 0, read + Format.TagSize);
                if (last)
                {
                    break;
                }
            }

            output.Flush();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plain);
            CryptographicOperations.ZeroMemory(fileKey);
        }
    }

    public static async Task EncryptAsync(Stream input, Stream output, byte[] header, byte[] fileKey, CancellationToken cancellationToken)
    {
        byte[] plain = new byte[ChunkCipher.ChunkSize];
        byte[] box = new byte[ChunkCipher.SealedChunkSize];
        try
        {
            using var cipher = new ChunkCipher(fileKey, header);
            await output.WriteAsync(header, cancellationToken).ConfigureAwait(false);
            while (true)
            {
                int read = await input.ReadAtLeastAsync(plain, plain.Length, throwOnEndOfStream: false, cancellationToken).ConfigureAwait(false);
                bool last = read < plain.Length;
                cipher.Seal(plain.AsSpan(0, read), box, last);
                await output.WriteAsync(box.AsMemory(0, read + Format.TagSize), cancellationToken).ConfigureAwait(false);
                if (last)
                {
                    break;
                }
            }

            await output.FlushAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plain);
            CryptographicOperations.ZeroMemory(fileKey);
        }
    }

    /// <summary>Reads and checks the stream header. Returns the whole header.</summary>
    public static byte[] ReadHeader(Stream input, BlobKind kind, int size)
    {
        byte[] header = new byte[size];
        int read = input.ReadAtLeast(header.AsSpan(0, 2), 2, throwOnEndOfStream: false);
        CheckHeaderStart(header, read, kind);
        if (input.ReadAtLeast(header.AsSpan(2), size - 2, throwOnEndOfStream: false) != size - 2)
        {
            throw Errors.Truncated();
        }

        return header;
    }

    public static async Task<byte[]> ReadHeaderAsync(Stream input, BlobKind kind, int size, CancellationToken cancellationToken)
    {
        byte[] header = new byte[size];
        int read = await input.ReadAtLeastAsync(header.AsMemory(0, 2), 2, throwOnEndOfStream: false, cancellationToken).ConfigureAwait(false);
        CheckHeaderStart(header, read, kind);
        if (await input.ReadAtLeastAsync(header.AsMemory(2), size - 2, throwOnEndOfStream: false, cancellationToken).ConfigureAwait(false) != size - 2)
        {
            throw Errors.Truncated();
        }

        return header;
    }

    public static void Decrypt(Stream input, Stream output, byte[] header, List<byte[]> candidateKeys, bool password)
    {
        byte[] box = new byte[ChunkCipher.SealedChunkSize];
        byte[] plain = new byte[ChunkCipher.ChunkSize];
        ChunkCipher? cipher = null;
        try
        {
            int read = input.ReadAtLeast(box, box.Length, throwOnEndOfStream: false);
            bool last = read < box.Length;
            cipher = OpenFirstChunk(box.AsSpan(0, read), plain, last, header, candidateKeys, password);
            output.Write(plain, 0, read - Format.TagSize);

            while (!last)
            {
                read = input.ReadAtLeast(box, box.Length, throwOnEndOfStream: false);
                last = read < box.Length;
                OpenChunk(cipher, box.AsSpan(0, read), plain, last);
                output.Write(plain, 0, read - Format.TagSize);
            }

            // Bytes appended to the stream become part of the final chunk and fail authentication above. This
            // check only guards against streams that return more data after reporting their end.
            if (input.ReadAtLeast(box.AsSpan(0, 1), 1, throwOnEndOfStream: false) != 0)
            {
                throw Errors.InvalidFormat("there is extra data after the end of the encrypted content.");
            }

            output.Flush();
        }
        finally
        {
            cipher?.Dispose();
            CryptographicOperations.ZeroMemory(plain);
            candidateKeys.ForEach(k => CryptographicOperations.ZeroMemory(k));
        }
    }

    public static async Task DecryptAsync(Stream input, Stream output, byte[] header, List<byte[]> candidateKeys, bool password, CancellationToken cancellationToken)
    {
        byte[] box = new byte[ChunkCipher.SealedChunkSize];
        byte[] plain = new byte[ChunkCipher.ChunkSize];
        ChunkCipher? cipher = null;
        try
        {
            int read = await input.ReadAtLeastAsync(box, box.Length, throwOnEndOfStream: false, cancellationToken).ConfigureAwait(false);
            bool last = read < box.Length;
            cipher = OpenFirstChunk(box.AsSpan(0, read), plain, last, header, candidateKeys, password);
            await output.WriteAsync(plain.AsMemory(0, read - Format.TagSize), cancellationToken).ConfigureAwait(false);

            while (!last)
            {
                read = await input.ReadAtLeastAsync(box, box.Length, throwOnEndOfStream: false, cancellationToken).ConfigureAwait(false);
                last = read < box.Length;
                OpenChunk(cipher, box.AsSpan(0, read), plain, last);
                await output.WriteAsync(plain.AsMemory(0, read - Format.TagSize), cancellationToken).ConfigureAwait(false);
            }

            if (await input.ReadAtLeastAsync(box.AsMemory(0, 1), 1, throwOnEndOfStream: false, cancellationToken).ConfigureAwait(false) != 0)
            {
                throw Errors.InvalidFormat("there is extra data after the end of the encrypted content.");
            }

            await output.FlushAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            cipher?.Dispose();
            CryptographicOperations.ZeroMemory(plain);
            candidateKeys.ForEach(k => CryptographicOperations.ZeroMemory(k));
        }
    }

    private static void CheckHeaderStart(byte[] header, int read, BlobKind kind)
    {
        if (read < 2)
        {
            throw read == 0 ? Errors.InvalidFormat("the input is empty.") : Errors.Truncated();
        }

        Errors.ExpectKind(header.AsSpan(0, 2), kind);
    }

    /// <summary>The first chunk decides which candidate key is right, before anything is written.</summary>
    private static ChunkCipher OpenFirstChunk(ReadOnlySpan<byte> chunk, Span<byte> plain, bool last, byte[] header, List<byte[]> candidateKeys, bool password)
    {
        if (chunk.Length < Format.TagSize)
        {
            throw Errors.Truncated();
        }

        foreach (byte[] fileKey in candidateKeys)
        {
            var cipher = new ChunkCipher(fileKey, header);
            if (cipher.TryOpen(chunk, plain, last))
            {
                return cipher;
            }

            cipher.Dispose();
        }

        throw password ? Errors.WrongPassword() : Errors.AuthenticationFailed("Decryption");
    }

    private static void OpenChunk(ChunkCipher cipher, ReadOnlySpan<byte> chunk, Span<byte> plain, bool last)
    {
        if (chunk.Length < Format.TagSize)
        {
            throw Errors.Truncated();
        }

        if (!cipher.TryOpen(chunk, plain, last))
        {
            throw Errors.AuthenticationFailed("Decryption");
        }
    }
}
