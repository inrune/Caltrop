using System.Reflection;
using System.Security.Cryptography;
using System.Text;

namespace CaltropSecurity.Internal;

/// <summary>
/// Caltrop's own folder, where it keeps its key (caltrop.key), secrets (secrets.vault) and log (caltrop.log),
/// so apps need no setup. Everything is created on first use.
/// </summary>
internal static class Home
{
    public const string KeyFileName = "caltrop.key";
    public const string SecretsFileName = "secrets.vault";
    public const string LogFileName = "caltrop.log";
    private const string ReadMeFileName = "README.txt";

    private static readonly Lock s_folderGate = new();
    private static readonly Lock s_keyGate = new();
    private static readonly Lock s_secretsGate = new();
    private static readonly Lock s_logGate = new();

    [ThreadStatic]
    private static bool t_openingLog;

    private static string? s_folder;
    private static bool s_folderSet;
    private static CaltropVault? s_secrets;
    private static CaltropLog? s_log;

    /// <summary>The folder in use, or <see langword="null"/> if Caltrop has nowhere safe to keep its files.</summary>
    public static string? Folder
    {
        get
        {
            lock (s_folderGate)
            {
                return s_folderSet ? s_folder : DefaultFolder();
            }
        }

        set
        {
            lock (s_folderGate)
            {
                s_folder = string.IsNullOrWhiteSpace(value) ? null : Path.GetFullPath(value);
                s_folderSet = true;
            }

            CloseOpenFiles();
        }
    }

    /// <summary><see langword="true"/> inside the official .NET container images.</summary>
    public static bool InContainer =>
        string.Equals(Environment.GetEnvironmentVariable("DOTNET_RUNNING_IN_CONTAINER"), "true", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Loads the key file in the folder. If there is none and <paramref name="create"/> is set, makes a new key and
    /// saves it first. Returns <see langword="null"/> if there is no folder, or no file and nothing should be created.
    /// </summary>
    public static CaltropKeyRing? LoadKey(bool create)
    {
        string? folder = Folder;
        if (folder is null)
        {
            return null;
        }

        string path = Path.Combine(folder, KeyFileName);
        lock (s_keyGate)
        {
            if (!File.Exists(path))
            {
                if (!create)
                {
                    return null;
                }

                MakeKeyFile(folder, path);
            }

            return ReadKeyFile(path);
        }
    }

    /// <summary>The message for when there is no key and nowhere to make one.</summary>
    public static string NoKeyMessage() =>
        InContainer && string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable(Caltrop.FolderEnvironmentVariable))
            ? "Caltrop has no key. It is running in a container, where a key file it made for itself would be lost " +
              $"when the container is replaced, and your data with it. Set the {Caltrop.KeyEnvironmentVariable} environment " +
              "variable to a key (make one with CaltropKey.Generate().Export()), or set " +
              $"{Caltrop.FolderEnvironmentVariable} to a folder on a volume that is kept."
            : $"Caltrop has no key and no folder to keep one in. Set the {Caltrop.KeyEnvironmentVariable} environment variable " +
              $"to a key (make one with CaltropKey.Generate().Export()), set {Caltrop.FolderEnvironmentVariable} or " +
              "Caltrop.Folder to a folder, or call Caltrop.UseKey(...) when your app starts.";

    /// <summary>The vault behind <see cref="Caltrop.Secrets"/>, opened (or created) on first use.</summary>
    public static CaltropVault Secrets()
    {
        CaltropKeyRing keys = Caltrop.DefaultKeys;
        lock (s_secretsGate)
        {
            if (s_secrets is not null)
            {
                return s_secrets;
            }

            string folder = RequireFolder("keep secrets in");
            CreateFolder(folder);
            s_secrets = OpenOrCreateSecrets(Path.Combine(folder, SecretsFileName), keys);
            return s_secrets;
        }
    }

    /// <summary>The log behind <see cref="Caltrop.Log(string)"/>, opened (or created) on first use.</summary>
    public static CaltropLog Log()
    {
        CaltropKeyRing keys = Caltrop.DefaultKeys;
        lock (s_logGate)
        {
            if (s_log is not null)
            {
                return s_log;
            }

            string folder = RequireFolder("keep its log in");
            CreateFolder(folder);
            string path = Path.Combine(folder, LogFileName);
            t_openingLog = true;
            try
            {
                s_log = new CaltropLog(path, CaltropLog.KeyFor(path, keys));
            }
            finally
            {
                t_openingLog = false;
            }

            return s_log;
        }
    }

    /// <summary>Caltrop's own log for recording an alarm, or <see langword="null"/> if it cannot be used. Never throws.</summary>
    public static CaltropLog? TryLog()
    {
        if (t_openingLog || Folder is null)
        {
            return null; // nowhere to write, or the alarm is about the log being opened
        }

        try
        {
            return Log();
        }
#pragma warning disable CA1031 // Recording an alarm must never throw.
        catch (Exception)
#pragma warning restore CA1031
        {
            return null;
        }
    }

    /// <summary>Closes the automatic vault and log, for example when the folder changes.</summary>
    public static void CloseOpenFiles()
    {
        lock (s_secretsGate)
        {
            s_secrets?.Dispose();
            s_secrets = null;
        }

        lock (s_logGate)
        {
            s_log?.Dispose();
            s_log = null;
        }
    }

    /// <summary>Goes back to the default folder and closes everything (tests only).</summary>
    public static void ResetForTests()
    {
        CloseOpenFiles();
        lock (s_folderGate)
        {
            s_folder = null;
            s_folderSet = false;
        }
    }

    private static string? DefaultFolder()
    {
        string? chosen = Environment.GetEnvironmentVariable(Caltrop.FolderEnvironmentVariable);
        if (!string.IsNullOrWhiteSpace(chosen))
        {
            return Path.GetFullPath(chosen.Trim());
        }

        if (InContainer)
        {
            return null; // a container's own disk is thrown away with it: never keep a key there by surprise
        }

        string appData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData, Environment.SpecialFolderOption.DoNotVerify);
        return string.IsNullOrEmpty(appData) ? null : Path.Combine(appData, "Caltrop", AppName());
    }

    private static string AppName() => Caltrop.Safe.FileName(Assembly.GetEntryAssembly()?.GetName().Name, fallback: "App");

    private static string RequireFolder(string purpose) =>
        Folder ?? throw new InvalidOperationException(
            $"Caltrop has no folder to {purpose}. Set {Caltrop.FolderEnvironmentVariable} or Caltrop.Folder to a folder that is kept.");

    private static void CreateFolder(string folder)
    {
        try
        {
            if (OperatingSystem.IsWindows())
            {
                Directory.CreateDirectory(folder);
            }
            else
            {
                Directory.CreateDirectory(folder, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new InvalidOperationException(
                $"Caltrop could not create its folder {folder}: {ex.Message} Set {Caltrop.FolderEnvironmentVariable} or Caltrop.Folder to a folder this app can write to.",
                ex);
        }
    }

    /// <summary>
    /// Makes a new key file. Two copies of the app starting at the same moment take turns (with a lock file), so
    /// they always agree on one key. The key is written to a temporary file first and then moved into place, so
    /// nobody ever sees half a key.
    /// </summary>
    private static void MakeKeyFile(string folder, string path)
    {
        CreateFolder(folder);
        try
        {
            using (SharedFile.Lock(path))
            {
                if (!File.Exists(path))
                {
                    using CaltropKey key = CaltropKey.Generate();
                    byte[] text = Encoding.UTF8.GetBytes(key.Export() + Environment.NewLine);
                    try
                    {
                        SharedFile.WriteAtomically(path, text, replace: false);
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(text);
                    }
                }
            }

            SharedFile.TryDelete(path + ".lock"); // only needed while the key is made
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new InvalidOperationException(
                $"Caltrop could not save its key in {folder}: {ex.Message} Set {Caltrop.FolderEnvironmentVariable} or Caltrop.Folder to a folder this " +
                $"app can write to, or give Caltrop a key with the {Caltrop.KeyEnvironmentVariable} environment variable or Caltrop.UseKey(...).",
                ex);
        }

        TryWriteReadMe(folder);
    }

    private static CaltropVault OpenOrCreateSecrets(string path, CaltropKeyRing keys)
    {
        if (!File.Exists(path))
        {
            try
            {
                return CaltropVault.Create(path, keys.Primary);
            }
            catch (IOException) when (File.Exists(path))
            {
                // Another copy of the app made it a moment ago: open theirs.
            }
        }

        return CaltropVault.Open(path, keys);
    }

    private static CaltropKeyRing ReadKeyFile(string path)
    {
        string text;
        try
        {
            text = File.ReadAllText(path).Trim();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new InvalidOperationException($"Caltrop could not read its key file {path}: {ex.Message} Check that this app is allowed to read it.", ex);
        }

        try
        {
            return CaltropKeyRing.Parse(text);
        }
        catch (CaltropException ex)
        {
            throw new CaltropException(
                CaltropErrorCode.InvalidKey,
                $"Caltrop's key file {path} is damaged ({ex.Message}) Restore it from a backup. Do not delete it: data encrypted with it cannot be read without it.",
                ex);
        }
    }

    /// <summary>Explains the folder to anyone who finds it. Nothing depends on it, so a failure is ignored.</summary>
    private static void TryWriteReadMe(string folder)
    {
        string path = Path.Combine(folder, ReadMeFileName);
        try
        {
            if (File.Exists(path))
            {
                return;
            }

            File.WriteAllText(path, $"""
                This folder belongs to Caltrop, the security library used by {AppName()}.

                {KeyFileName}    The key that protects this app's data. Keep it secret and back it up:
                               if it is lost, everything encrypted with it is lost too.
                {SecretsFileName}  Secrets saved with Caltrop.Secrets, encrypted with the key.
                {LogFileName}    A tamper-proof log of security events and alarms.
                *.lock         Let several copies of the app use these files at once. They hold no data.

                To use the same key on another computer, copy {KeyFileName} into the same folder there,
                or set the {Caltrop.KeyEnvironmentVariable} environment variable to its contents.

                """);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Only a help file.
        }
    }
}
