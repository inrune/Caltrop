using System.Runtime.CompilerServices;
using CaltropSecurity.Internal;

namespace CaltropSecurity.Tests;

/// <summary>
/// Tests that change process-wide state (the default key, Caltrop's folder, trap settings, a lockdown) belong to
/// this collection. xUnit runs it on its own, after all the other tests, one test at a time.
/// </summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class GlobalState
{
    public const string Name = "Global state";

    /// <summary>Caltrop's folder for the whole test run, so tests never touch the real app data folder.</summary>
    public static string TestFolder { get; } =
        Path.Combine(Path.GetTempPath(), $"caltrop-tests-{Environment.ProcessId}-{Guid.NewGuid():N}");

    /// <summary>Puts every process-wide setting back to normal.</summary>
    public static void Reset()
    {
        Caltrop.Traps.ResetForTests();
        Caltrop.ResetDefaultKeys();
        Caltrop.Decoys.ClearWatched();
        Home.ResetForTests();
        Environment.SetEnvironmentVariable(Caltrop.KeyEnvironmentVariable, null);
        Environment.SetEnvironmentVariable(Caltrop.FolderEnvironmentVariable, null);
        Environment.SetEnvironmentVariable("DOTNET_RUNNING_IN_CONTAINER", null);
        Caltrop.Folder = TestFolder;
        Caltrop.Passwords.Rules = CaltropPasswordRules.Default;
        Caltrop.Passwords.Lockout = new CaltropLockout();
        SharedFile.Patience = TimeSpan.FromSeconds(10);
    }

    /// <summary>Forgets the loaded key and closes Caltrop's files, as if the app had restarted. Keeps the folder.</summary>
    public static void Restart()
    {
        Caltrop.ResetDefaultKeys();
        Home.CloseOpenFiles();
    }

#pragma warning disable CA2255 // A test assembly may set up the process like this.
    [ModuleInitializer]
#pragma warning restore CA2255
    internal static void UseTestFolder()
    {
        Caltrop.Folder = TestFolder;
        AppDomain.CurrentDomain.ProcessExit += (_, _) =>
        {
            try
            {
                Home.CloseOpenFiles();
                Directory.Delete(TestFolder, recursive: true);
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
        };
    }
}

/// <summary>Records every alarm raised while it is alive.</summary>
internal sealed class AlarmRecorder : IDisposable
{
    private readonly List<CaltropAlarm> _alarms = [];

    public AlarmRecorder() => Caltrop.Traps.Alarm += OnAlarm;

    public IReadOnlyList<CaltropAlarm> Alarms
    {
        get
        {
            lock (_alarms)
            {
                return [.. _alarms];
            }
        }
    }

    public void Dispose() => Caltrop.Traps.Alarm -= OnAlarm;

    private void OnAlarm(object? sender, CaltropAlarm alarm)
    {
        lock (_alarms)
        {
            _alarms.Add(alarm);
        }
    }
}

/// <summary>A clock tests can move by hand.</summary>
internal sealed class ManualClock : TimeProvider
{
    private DateTimeOffset _now = new(2026, 11, 16, 12, 0, 0, TimeSpan.Zero);

    public override DateTimeOffset GetUtcNow() => _now;

    public void Advance(TimeSpan by) => _now += by;
}

/// <summary>A temporary folder, deleted when disposed.</summary>
internal sealed class TempFolder : IDisposable
{
    public TempFolder()
    {
        Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "caltrop-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path);
    }

    public string Path { get; }

    public string File(string name) => System.IO.Path.Combine(Path, name);

    public void Dispose()
    {
        try
        {
            Directory.Delete(Path, recursive: true);
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }
}
