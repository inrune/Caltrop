using System.Diagnostics;
using System.Security.Cryptography;

namespace CaltropSecurity.Internal;

/// <summary>
/// Safe file handling when several programs, or several copies of one app, use the same files at once.
/// </summary>
/// <remarks>
/// A program that changes a vault or a log first takes "&lt;file&gt;.lock", which it opens exclusively, so changes
/// happen one at a time and none is lost. Reading needs no lock: a vault is only ever replaced whole, and a log
/// only ever has lines added. A file that is busy (another program has it locked, or a virus scanner is reading
/// it) is tried again for up to <see cref="Patience"/>.
/// </remarks>
internal static class SharedFile
{
    private const UnixFileMode PrivateFile = UnixFileMode.UserRead | UnixFileMode.UserWrite;

    // Windows: ERROR_SHARING_VIOLATION and ERROR_LOCK_VIOLATION. Linux and macOS report EWOULDBLOCK (11, or 35 on macOS).
    private const int SharingViolation = unchecked((int)0x80070020);
    private const int LockViolation = unchecked((int)0x80070021);

    /// <summary>How long to keep trying a file that another program has busy. Tests shorten it.</summary>
    public static TimeSpan Patience { get; set; } = TimeSpan.FromSeconds(10);

    /// <summary>Takes the lock for <paramref name="path"/>, waiting while another program has it. Dispose the result to release it.</summary>
    public static FileStream Lock(string path)
    {
        string lockPath = path + ".lock";
        return Retry(lockPath, () => new FileStream(lockPath, Options(FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None)));
    }

    /// <summary>Opens a file for reading without getting in the way of anyone writing it.</summary>
    public static FileStream OpenRead(string path) =>
        Retry(path, () => new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete));

    /// <summary>Like <see cref="OpenRead"/>, but returns <see langword="null"/> if there is no such file.</summary>
    public static FileStream? TryOpenRead(string path)
    {
        try
        {
            return OpenRead(path);
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
        {
            return null;
        }
    }

    /// <summary>Options to open a file with. A file they create is readable only by this user on Linux and macOS.</summary>
    public static FileStreamOptions Options(FileMode mode, FileAccess access, FileShare share, int bufferSize = 4096)
    {
        var options = new FileStreamOptions { Mode = mode, Access = access, Share = share, BufferSize = bufferSize };
        if (!OperatingSystem.IsWindows() && mode is not (FileMode.Open or FileMode.Truncate))
        {
            options.UnixCreateMode = PrivateFile;
        }

        return options;
    }

    /// <summary>
    /// Writes a whole file safely: to a temporary file next to it, flushed to disk, then moved into place. Anyone
    /// reading it sees the old file or the new one, never half of one, and a crash never leaves a damaged file.
    /// </summary>
    /// <param name="path">The file.</param>
    /// <param name="content">Its new content.</param>
    /// <param name="replace"><see langword="false"/> to fail if the file already exists.</param>
    public static void WriteAtomically(string path, ReadOnlySpan<byte> content, bool replace = true)
    {
        string temp = TempPathFor(path);
        try
        {
            using (var stream = new FileStream(temp, Options(FileMode.CreateNew, FileAccess.Write, FileShare.None)))
            {
                stream.Write(content);
                stream.Flush(flushToDisk: true);
            }

            MoveIntoPlace(temp, path, replace);
        }
        catch
        {
            TryDelete(temp);
            throw;
        }
    }

    /// <summary>Moves a finished temporary file into place, trying again while something else has the file open.</summary>
    public static void MoveIntoPlace(string temp, string path, bool replace = true) =>
        Retry(path, () =>
        {
            File.Move(temp, path, replace);
            return true;
        });

    /// <summary>A temporary file name in the same folder as <paramref name="path"/>, so moving it into place is instant.</summary>
    public static string TempPathFor(string path)
    {
        string folder = Path.GetDirectoryName(path) ?? ".";
        return Path.Combine(folder, $".{Path.GetFileName(path)}.{RandomNumberGenerator.GetHexString(12, lowercase: true)}.tmp");
    }

    /// <summary>Deletes a file if it can. Never throws.</summary>
    public static void TryDelete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (IOException)
        {
            // Best effort: whatever went wrong first matters more.
        }
        catch (UnauthorizedAccessException)
        {
            // Best effort.
        }
    }

    /// <summary>Creates the folder a file goes in, if it does not exist yet.</summary>
    public static void CreateFolderFor(string path)
    {
        string? folder = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(folder))
        {
            Directory.CreateDirectory(folder);
        }
    }

    /// <summary>Runs <paramref name="action"/>, trying again for a while if the file is busy.</summary>
    public static T Retry<T>(string path, Func<T> action)
    {
        long started = Stopwatch.GetTimestamp();
        int delay = 1;
        while (true)
        {
            try
            {
                return action();
            }
            catch (Exception ex) when (IsBusy(ex))
            {
                // On Windows, "access denied" can mean a virus scanner has the file for a moment, or a real
                // permissions problem; give it a short while only.
                TimeSpan limit = ex is UnauthorizedAccessException ? Patience / 10 : Patience;
                if (Stopwatch.GetElapsedTime(started) >= limit)
                {
                    if (ex is UnauthorizedAccessException)
                    {
                        throw;
                    }

                    throw new IOException(
                        $"Caltrop could not use {path}: another program has kept it busy for over {Patience.TotalSeconds:0.#} seconds. Try again, or close the program that is using it.",
                        ex);
                }

                Thread.Sleep(delay);
                delay = Math.Min(delay * 2, 50);
            }
        }
    }

    private static bool IsBusy(Exception ex) => ex switch
    {
        IOException io when OperatingSystem.IsWindows() => io.HResult is SharingViolation or LockViolation,
        IOException io => io.HResult is 11 or 35,
        UnauthorizedAccessException => OperatingSystem.IsWindows(),
        _ => false,
    };
}
