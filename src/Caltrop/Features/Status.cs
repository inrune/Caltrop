using System.Globalization;
using System.Text;
using CaltropSecurity.Internal;

public static partial class Caltrop
{
    /// <summary>
    /// Checks that Caltrop is set up and working: Caltrop.dll's self-check, where the key comes from (and which
    /// file to back up), the folder, the log, the secrets and the traps. It never makes a key or any file, so it is
    /// safe to call at any time: print it at startup, or when something does not work.
    /// </summary>
    /// <returns>What was found. <see cref="CaltropStatus.Ok"/> says whether all is well; <c>ToString()</c> gives the whole report.</returns>
    /// <example>
    /// <code>
    /// Console.WriteLine(Caltrop.Status());
    /// // Caltrop 1.0.0: everything is fine.
    /// //   Caltrop.dll  not changed since it was built
    /// //   Key          C:\Users\me\AppData\Local\Caltrop\MyApp\caltrop.key (back this file up)
    /// //   ...
    /// </code>
    /// </example>
    /// <remarks>
    /// A changed Caltrop.dll, log or secrets file still sets off its alarm, as it would anywhere else. The log is
    /// checked in full, so a very large log takes a moment.
    /// </remarks>
    public static CaltropStatus Status()
    {
        var status = new CaltropStatus(VersionText());
        if (Traps.IsLockedDown)
        {
            status.Problem("Lockdown", $"Caltrop locked itself down after this alarm: {Traps.LockedDownBy}. Restart the app.");
            return status;
        }

        switch (Tamper.CheckCaltrop())
        {
            case CaltropIntegrity.Intact:
                status.Add("Caltrop.dll", "not changed since it was built");
                break;
            case CaltropIntegrity.Changed:
                status.Problem("Caltrop.dll", "It has been changed since it was built. Download a fresh copy and check its SHA-256.");
                break;
            default:
                status.Add("Caltrop.dll", "cannot check itself in this kind of app (single-file or native)");
                break;
        }

        string? folder = Folder;
        CaltropKeyRing? keys = null;
        try
        {
            keys = DescribeDefaultKeys(out string source);
            if (keys is not null)
            {
                status.Add("Key", source);
            }
            else if (folder is null)
            {
                status.Problem("Key", Home.NoKeyMessage());
            }
            else
            {
                status.Add("Key", $"none yet: Caltrop makes {Path.Combine(folder, Home.KeyFileName)} the first time it needs one");
            }
        }
        catch (Exception ex) when (ex is CaltropException or IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            status.Problem("Key", ex.Message);
        }

        if (folder is null)
        {
            status.Add("Folder", $"none (in a container, set {FolderEnvironmentVariable} to a kept folder to use Caltrop.Secrets and Caltrop.Log)");
            AddTraps(status);
            return status;
        }

        status.Add("Folder", Directory.Exists(folder) ? folder : $"{folder} (made when first needed)");
        CheckFile(status, "Log", Path.Combine(folder, Home.LogFileName), keys, path =>
        {
            CaltropLogCheck check = CaltropLog.Verify(path, CaltropLog.KeyFor(path, keys!));
            return check.IsIntact ? Plural(check.Entries, "entry", "entries") + ", none changed" : throw new InvalidDataException($"It was tampered with: {check.Problem}");
        });
        CheckFile(status, "Secrets", Path.Combine(folder, Home.SecretsFileName), keys, path =>
        {
            using CaltropVault vault = CaltropVault.Open(path, keys!);
            return Plural(vault.Count, "secret", "secrets");
        });
        AddTraps(status);
        return status;
    }

    private static void CheckFile(CaltropStatus status, string name, string path, CaltropKeyRing? keys, Func<string, string> check)
    {
        if (!File.Exists(path))
        {
            status.Add(name, "none yet");
            return;
        }

        if (keys is null)
        {
            status.Problem(name, $"{path} exists, but there is no key to open it.");
            return;
        }

        try
        {
            status.Add(name, check(path));
        }
        catch (Exception ex) when (ex is CaltropException or IOException or UnauthorizedAccessException or InvalidDataException)
        {
            status.Problem(name, $"{path}: {ex.Message}");
        }
    }

    private static void AddTraps(CaltropStatus status)
    {
        string log = Traps.Log is { } custom ? custom.Path : "Caltrop's log";
        string handlers = Plural(Traps.HandlerCount, "alarm handler", "alarm handlers");
        string lockDown = Traps.LockDownOn == CaltropAlarmKind.None ? "no lockdown" : $"lockdown on {Traps.LockDownOn}";
        status.Add("Traps", $"alarms go to {log}; {handlers}; {lockDown}");
    }

    private static string Plural(long count, string one, string many) =>
        count.ToString(CultureInfo.InvariantCulture) + " " + (count == 1 ? one : many);

    private static string VersionText() =>
        typeof(Caltrop).Assembly.GetName().Version is { } version ? $"{version.Major}.{version.Minor}.{version.Build}" : "?";
}

/// <summary>What <see cref="Caltrop.Status"/> found. Print it to see the whole report.</summary>
public sealed class CaltropStatus
{
    private readonly List<(string Name, string Value)> _lines = [];
    private readonly List<string> _problems = [];

    internal CaltropStatus(string version) => Version = version;

    /// <summary><see langword="true"/> if nothing is wrong.</summary>
    public bool Ok => _problems.Count == 0;

    /// <summary>What is wrong, each with what to do about it. Empty if nothing is.</summary>
    public IReadOnlyList<string> Problems => _problems;

    /// <summary>The version of Caltrop.dll, such as <c>1.0.0</c>.</summary>
    public string Version { get; }

    /// <summary>The whole report: a summary line, then one line per part.</summary>
    public override string ToString()
    {
        var text = new StringBuilder();
        text.Append(CultureInfo.InvariantCulture, $"Caltrop {Version}: ");
        text.Append(Ok ? "everything is fine." : _problems.Count == 1 ? "1 problem." : $"{_problems.Count} problems.");
        foreach ((string name, string value) in _lines)
        {
            text.AppendLine().Append("  ").Append(name.PadRight(12)).Append(' ').Append(value);
        }

        return text.ToString();
    }

    internal void Add(string name, string value) => _lines.Add((name, value));

    internal void Problem(string name, string problem)
    {
        _problems.Add(problem);
        _lines.Add((name, "PROBLEM: " + problem));
    }
}
