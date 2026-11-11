using System.Security.Cryptography;
using CaltropSecurity.Internal;

namespace CaltropSecurity;

public static partial class Caltrop
{
    /// <summary>
    /// Encrypts files and streams of any size without loading them into memory. The data is processed in 64 KiB
    /// chunks, each authenticated, so changes, reordering or cutting off the end are all detected.
    /// </summary>
    /// <example>
    /// <code>
    /// Caltrop.Files.EncryptFile("report.pdf", "report.pdf.caltrop", key);
    /// Caltrop.Files.DecryptFile("report.pdf.caltrop", "report.pdf", key);
    ///
    /// await using var upload = file.OpenReadStream();
    /// await using var stored = File.Create(path);
    /// await Caltrop.Files.EncryptAsync(upload, stored, key);
    /// </code>
    /// </example>
    /// <remarks>
    /// The file methods write to a temporary file and only replace the output once everything succeeded, so a
    /// failed or tampered decryption never leaves a partial file. Decrypted files are created readable only by the
    /// current user on Linux and macOS. The stream methods write as they go: if a stream decryption throws, discard
    /// what was written. Streams passed in are not closed. The output is the input size plus 30 bytes, plus 16 bytes
    /// per 64 KiB.
    /// </remarks>
    public static class Files
    {
        // ---------------------------------------------------------------- streams, secret key

        /// <summary>Encrypts everything read from <paramref name="input"/> into <paramref name="output"/>.</summary>
        /// <param name="input">The data to encrypt, read to the end.</param>
        /// <param name="output">Where the encrypted data is written.</param>
        /// <param name="key">The secret key.</param>
        public static void Encrypt(Stream input, Stream output, CaltropKey key)
        {
            CheckStreams(input, output);
            byte[] header = StreamHeaders.NewKeyHeader(key, out byte[] fileKey);
            StreamCrypto.Encrypt(input, output, header, fileKey);
        }

        /// <summary>Decrypts data made by <see cref="Encrypt(Stream, Stream, CaltropKey)"/>.</summary>
        /// <param name="input">The encrypted data.</param>
        /// <param name="output">Where the original data is written.</param>
        /// <param name="key">The key it was encrypted with.</param>
        /// <exception cref="CaltropException">The data was changed, cut off, or encrypted with a different key.</exception>
        public static void Decrypt(Stream input, Stream output, CaltropKey key) =>
            Decrypt(input, output, KeyList.Single(key, nameof(key)));

        /// <summary>Decrypts data made with any key in <paramref name="keys"/>. Use this during key rotation.</summary>
        /// <param name="input">The encrypted data.</param>
        /// <param name="output">Where the original data is written.</param>
        /// <param name="keys">The candidate keys, for example a <see cref="CaltropKeyRing"/>.</param>
        /// <exception cref="CaltropException">The data was changed, cut off, or none of the keys can decrypt it.</exception>
        public static void Decrypt(Stream input, Stream output, IEnumerable<CaltropKey> keys)
        {
            CheckStreams(input, output);
            IReadOnlyList<CaltropKey> list = KeyList.From(keys, nameof(keys));
            byte[] header = StreamCrypto.ReadHeader(input, BlobKind.SecretKeyStream, StreamHeaders.KeyHeaderSize);
            StreamCrypto.Decrypt(input, output, header, StreamHeaders.KeyCandidates(header, list), password: false);
        }

        /// <summary>Encrypts everything read from <paramref name="input"/> into <paramref name="output"/>.</summary>
        /// <param name="input">The data to encrypt, read to the end.</param>
        /// <param name="output">Where the encrypted data is written.</param>
        /// <param name="key">The secret key.</param>
        /// <param name="cancellationToken">Cancels the operation.</param>
        /// <returns>A task that completes when everything is written.</returns>
        public static Task EncryptAsync(Stream input, Stream output, CaltropKey key, CancellationToken cancellationToken = default)
        {
            CheckStreams(input, output);
            byte[] header = StreamHeaders.NewKeyHeader(key, out byte[] fileKey);
            return StreamCrypto.EncryptAsync(input, output, header, fileKey, cancellationToken);
        }

        /// <summary>Decrypts data made by <see cref="EncryptAsync(Stream, Stream, CaltropKey, CancellationToken)"/>.</summary>
        /// <param name="input">The encrypted data.</param>
        /// <param name="output">Where the original data is written.</param>
        /// <param name="key">The key it was encrypted with.</param>
        /// <param name="cancellationToken">Cancels the operation.</param>
        /// <returns>A task that completes when everything is written.</returns>
        /// <exception cref="CaltropException">The data was changed, cut off, or encrypted with a different key.</exception>
        public static Task DecryptAsync(Stream input, Stream output, CaltropKey key, CancellationToken cancellationToken = default) =>
            DecryptAsync(input, output, KeyList.Single(key, nameof(key)), cancellationToken);

        /// <summary>Decrypts data made with any key in <paramref name="keys"/>.</summary>
        /// <param name="input">The encrypted data.</param>
        /// <param name="output">Where the original data is written.</param>
        /// <param name="keys">The candidate keys.</param>
        /// <param name="cancellationToken">Cancels the operation.</param>
        /// <returns>A task that completes when everything is written.</returns>
        /// <exception cref="CaltropException">The data was changed, cut off, or none of the keys can decrypt it.</exception>
        public static Task DecryptAsync(Stream input, Stream output, IEnumerable<CaltropKey> keys, CancellationToken cancellationToken = default)
        {
            CheckStreams(input, output);
            IReadOnlyList<CaltropKey> list = KeyList.From(keys, nameof(keys));
            return DecryptWithKeysAsync(input, output, list, cancellationToken);
        }

        // ---------------------------------------------------------------- streams, password

        /// <summary>Encrypts a stream with a password (PBKDF2-HMAC-SHA256, 600,000 iterations).</summary>
        /// <param name="input">The data to encrypt, read to the end.</param>
        /// <param name="output">Where the encrypted data is written.</param>
        /// <param name="password">The password.</param>
        public static void EncryptWithPassword(Stream input, Stream output, string password)
        {
            CheckStreams(input, output);
            byte[] header = StreamHeaders.NewPasswordHeader(password, out byte[] fileKey);
            StreamCrypto.Encrypt(input, output, header, fileKey);
        }

        /// <summary>Decrypts a stream made by <see cref="EncryptWithPassword(Stream, Stream, string)"/>.</summary>
        /// <param name="input">The encrypted data.</param>
        /// <param name="output">Where the original data is written.</param>
        /// <param name="password">The password it was encrypted with.</param>
        /// <exception cref="CaltropException">The password is wrong, or the data was changed or cut off.</exception>
        public static void DecryptWithPassword(Stream input, Stream output, string password)
        {
            CheckStreams(input, output);
            ArgumentNullException.ThrowIfNull(password);
            byte[] header = StreamCrypto.ReadHeader(input, BlobKind.PasswordStream, StreamHeaders.PasswordHeaderSize);
            StreamCrypto.Decrypt(input, output, header, StreamHeaders.PasswordCandidate(header, password), password: true);
        }

        /// <summary>Encrypts a stream with a password.</summary>
        /// <param name="input">The data to encrypt, read to the end.</param>
        /// <param name="output">Where the encrypted data is written.</param>
        /// <param name="password">The password.</param>
        /// <param name="cancellationToken">Cancels the operation.</param>
        /// <returns>A task that completes when everything is written.</returns>
        public static Task EncryptWithPasswordAsync(Stream input, Stream output, string password, CancellationToken cancellationToken = default)
        {
            CheckStreams(input, output);
            byte[] header = StreamHeaders.NewPasswordHeader(password, out byte[] fileKey);
            return StreamCrypto.EncryptAsync(input, output, header, fileKey, cancellationToken);
        }

        /// <summary>Decrypts a stream made by <see cref="EncryptWithPasswordAsync(Stream, Stream, string, CancellationToken)"/>.</summary>
        /// <param name="input">The encrypted data.</param>
        /// <param name="output">Where the original data is written.</param>
        /// <param name="password">The password it was encrypted with.</param>
        /// <param name="cancellationToken">Cancels the operation.</param>
        /// <returns>A task that completes when everything is written.</returns>
        /// <exception cref="CaltropException">The password is wrong, or the data was changed or cut off.</exception>
        public static Task DecryptWithPasswordAsync(Stream input, Stream output, string password, CancellationToken cancellationToken = default)
        {
            CheckStreams(input, output);
            ArgumentNullException.ThrowIfNull(password);
            return DecryptWithPasswordCoreAsync(input, output, password, cancellationToken);
        }

        // ---------------------------------------------------------------- file paths

        /// <summary>Encrypts a file. <paramref name="outputPath"/> is replaced only if encryption succeeds.</summary>
        /// <param name="inputPath">The file to encrypt.</param>
        /// <param name="outputPath">Where to write the encrypted file. It may be the same as <paramref name="inputPath"/>.</param>
        /// <param name="key">The secret key.</param>
        public static void EncryptFile(string inputPath, string outputPath, CaltropKey key)
        {
            ArgumentNullException.ThrowIfNull(key);
            WriteViaTempFile(inputPath, outputPath, privateOutput: false, (input, output) => Encrypt(input, output, key));
        }

        /// <summary>Decrypts a file. <paramref name="outputPath"/> is replaced only if the whole file decrypts and verifies.</summary>
        /// <param name="inputPath">The encrypted file.</param>
        /// <param name="outputPath">Where to write the decrypted file. It may be the same as <paramref name="inputPath"/>.</param>
        /// <param name="key">The key it was encrypted with.</param>
        /// <exception cref="CaltropException">The file was changed, cut off, or encrypted with a different key.</exception>
        public static void DecryptFile(string inputPath, string outputPath, CaltropKey key)
        {
            ArgumentNullException.ThrowIfNull(key);
            WriteViaTempFile(inputPath, outputPath, privateOutput: true, (input, output) => Decrypt(input, output, key));
        }

        /// <summary>Decrypts a file made with any key in <paramref name="keys"/>.</summary>
        /// <param name="inputPath">The encrypted file.</param>
        /// <param name="outputPath">Where to write the decrypted file.</param>
        /// <param name="keys">The candidate keys.</param>
        /// <exception cref="CaltropException">The file was changed, cut off, or none of the keys can decrypt it.</exception>
        public static void DecryptFile(string inputPath, string outputPath, IEnumerable<CaltropKey> keys)
        {
            IReadOnlyList<CaltropKey> list = KeyList.From(keys, nameof(keys));
            WriteViaTempFile(inputPath, outputPath, privateOutput: true, (input, output) => Decrypt(input, output, list));
        }

        /// <summary>Encrypts a file with a password.</summary>
        /// <param name="inputPath">The file to encrypt.</param>
        /// <param name="outputPath">Where to write the encrypted file.</param>
        /// <param name="password">The password.</param>
        public static void EncryptFileWithPassword(string inputPath, string outputPath, string password)
        {
            PasswordKdf.ValidateNewPassword(password, nameof(password));
            WriteViaTempFile(inputPath, outputPath, privateOutput: false, (input, output) => EncryptWithPassword(input, output, password));
        }

        /// <summary>Decrypts a file made by <see cref="EncryptFileWithPassword(string, string, string)"/>.</summary>
        /// <param name="inputPath">The encrypted file.</param>
        /// <param name="outputPath">Where to write the decrypted file.</param>
        /// <param name="password">The password it was encrypted with.</param>
        /// <exception cref="CaltropException">The password is wrong, or the file was changed or cut off.</exception>
        public static void DecryptFileWithPassword(string inputPath, string outputPath, string password)
        {
            ArgumentNullException.ThrowIfNull(password);
            WriteViaTempFile(inputPath, outputPath, privateOutput: true, (input, output) => DecryptWithPassword(input, output, password));
        }

        /// <summary>Encrypts a file asynchronously. <paramref name="outputPath"/> is replaced only if encryption succeeds.</summary>
        /// <param name="inputPath">The file to encrypt.</param>
        /// <param name="outputPath">Where to write the encrypted file.</param>
        /// <param name="key">The secret key.</param>
        /// <param name="cancellationToken">Cancels the operation.</param>
        /// <returns>A task that completes when the file is written.</returns>
        public static Task EncryptFileAsync(string inputPath, string outputPath, CaltropKey key, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(key);
            return WriteViaTempFileAsync(inputPath, outputPath, privateOutput: false, (input, output) => EncryptAsync(input, output, key, cancellationToken), cancellationToken);
        }

        /// <summary>Decrypts a file asynchronously. <paramref name="outputPath"/> is replaced only if the whole file decrypts and verifies.</summary>
        /// <param name="inputPath">The encrypted file.</param>
        /// <param name="outputPath">Where to write the decrypted file.</param>
        /// <param name="key">The key it was encrypted with.</param>
        /// <param name="cancellationToken">Cancels the operation.</param>
        /// <returns>A task that completes when the file is written.</returns>
        /// <exception cref="CaltropException">The file was changed, cut off, or encrypted with a different key.</exception>
        public static Task DecryptFileAsync(string inputPath, string outputPath, CaltropKey key, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(key);
            return WriteViaTempFileAsync(inputPath, outputPath, privateOutput: true, (input, output) => DecryptAsync(input, output, key, cancellationToken), cancellationToken);
        }

        private static async Task DecryptWithKeysAsync(Stream input, Stream output, IReadOnlyList<CaltropKey> keys, CancellationToken cancellationToken)
        {
            byte[] header = await StreamCrypto.ReadHeaderAsync(input, BlobKind.SecretKeyStream, StreamHeaders.KeyHeaderSize, cancellationToken).ConfigureAwait(false);
            await StreamCrypto.DecryptAsync(input, output, header, StreamHeaders.KeyCandidates(header, keys), password: false, cancellationToken).ConfigureAwait(false);
        }

        private static async Task DecryptWithPasswordCoreAsync(Stream input, Stream output, string password, CancellationToken cancellationToken)
        {
            byte[] header = await StreamCrypto.ReadHeaderAsync(input, BlobKind.PasswordStream, StreamHeaders.PasswordHeaderSize, cancellationToken).ConfigureAwait(false);
            await StreamCrypto.DecryptAsync(input, output, header, StreamHeaders.PasswordCandidate(header, password), password: true, cancellationToken).ConfigureAwait(false);
        }

        private static void CheckStreams(Stream input, Stream output)
        {
            ArgumentNullException.ThrowIfNull(input);
            ArgumentNullException.ThrowIfNull(output);
            if (!input.CanRead)
            {
                throw new ArgumentException("The input stream must be readable.", nameof(input));
            }

            if (!output.CanWrite)
            {
                throw new ArgumentException("The output stream must be writable.", nameof(output));
            }
        }

        private static void WriteViaTempFile(string inputPath, string outputPath, bool privateOutput, Action<Stream, Stream> transform)
        {
            ArgumentException.ThrowIfNullOrEmpty(inputPath);
            ArgumentException.ThrowIfNullOrEmpty(outputPath);
            string target = Path.GetFullPath(outputPath);
            string temp = TempPathFor(target);
            try
            {
                // The input is closed before the move, so input and output may be the same file.
                using (var input = new FileStream(inputPath, FileMode.Open, FileAccess.Read, FileShare.Read, 1, FileOptions.SequentialScan))
                using (var output = new FileStream(temp, TempFileOptions(privateOutput, FileOptions.None)))
                {
                    transform(input, output);
                }

                File.Move(temp, target, overwrite: true);
            }
            catch
            {
                TryDelete(temp);
                throw;
            }
        }

        private static async Task WriteViaTempFileAsync(string inputPath, string outputPath, bool privateOutput, Func<Stream, Stream, Task> transform, CancellationToken cancellationToken)
        {
            ArgumentException.ThrowIfNullOrEmpty(inputPath);
            ArgumentException.ThrowIfNullOrEmpty(outputPath);
            string target = Path.GetFullPath(outputPath);
            string temp = TempPathFor(target);
            try
            {
                var input = new FileStream(inputPath, FileMode.Open, FileAccess.Read, FileShare.Read, 1, FileOptions.Asynchronous | FileOptions.SequentialScan);
                await using (input.ConfigureAwait(false))
                {
                    var output = new FileStream(temp, TempFileOptions(privateOutput, FileOptions.Asynchronous));
                    await using (output.ConfigureAwait(false))
                    {
                        await transform(input, output).ConfigureAwait(false);
                    }
                }

                cancellationToken.ThrowIfCancellationRequested();
                File.Move(temp, target, overwrite: true);
            }
            catch
            {
                TryDelete(temp);
                throw;
            }
        }

        private static string TempPathFor(string target)
        {
            string directory = Path.GetDirectoryName(target) ?? ".";
            return Path.Combine(directory, $".{Path.GetFileName(target)}.{RandomNumberGenerator.GetHexString(12, lowercase: true)}.tmp");
        }

        private static FileStreamOptions TempFileOptions(bool privateOutput, FileOptions options)
        {
            var result = new FileStreamOptions
            {
                Mode = FileMode.CreateNew,
                Access = FileAccess.Write,
                Share = FileShare.None,
                Options = options,
            };

            if (privateOutput && !OperatingSystem.IsWindows())
            {
                result.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
            }

            return result;
        }

        private static void TryDelete(string path)
        {
            try
            {
                File.Delete(path);
            }
            catch (IOException)
            {
                // Best effort: the original exception is more important.
            }
            catch (UnauthorizedAccessException)
            {
                // Best effort.
            }
        }
    }
}
