namespace CaltropSecurity.Tests;

[Collection(GlobalState.Name)]
public sealed class LockoutTests : IDisposable
{
    private readonly ManualClock _clock = new();

    public LockoutTests() => GlobalState.Reset();

    public void Dispose() => GlobalState.Reset();

    [Fact]
    public void Too_many_failures_lock_the_name_out_and_raise_one_alarm()
    {
        var lockout = new CaltropLockout { MaxFailures = 3, LockFor = TimeSpan.FromMinutes(10), SlowDown = false, Clock = _clock };
        using var alarms = new AlarmRecorder();

        Assert.False(lockout.Try("alice", () => false));
        Assert.False(lockout.Try("alice", () => false));
        Assert.False(lockout.IsLockedOut("alice"));
        Assert.False(lockout.Try("alice", () => false));

        Assert.True(lockout.IsLockedOut("alice"));
        Assert.Equal(TimeSpan.FromMinutes(10), lockout.TimeLeft("alice"));
        CaltropAlarm alarm = Assert.Single(alarms.Alarms);
        Assert.Equal(CaltropAlarmKind.TooManyAttempts, alarm.Kind);
        Assert.Equal("alice", alarm.Subject);
    }

    [Fact]
    public void While_locked_out_the_check_is_not_even_run()
    {
        var lockout = new CaltropLockout { MaxFailures = 1, SlowDown = false, Clock = _clock };
        lockout.RecordFailure("bob");
        bool ran = false;

        Assert.False(lockout.Try("bob", () => ran = true));
        Assert.False(ran);
    }

    [Fact]
    public void The_lockout_ends_after_LockFor()
    {
        var lockout = new CaltropLockout { MaxFailures = 1, LockFor = TimeSpan.FromMinutes(5), SlowDown = false, Clock = _clock };
        lockout.RecordFailure("carol");
        Assert.True(lockout.IsLockedOut("carol"));

        _clock.Advance(TimeSpan.FromMinutes(5));

        Assert.False(lockout.IsLockedOut("carol"));
        Assert.True(lockout.Try("carol", () => true));
    }

    [Fact]
    public void A_success_forgets_earlier_failures()
    {
        var lockout = new CaltropLockout { MaxFailures = 3, SlowDown = false, Clock = _clock };
        lockout.RecordFailure("dave");
        lockout.RecordFailure("dave");
        Assert.True(lockout.Try("dave", () => true));

        lockout.RecordFailure("dave");
        lockout.RecordFailure("dave");

        Assert.False(lockout.IsLockedOut("dave"));
    }

    [Fact]
    public void Old_failures_are_forgotten()
    {
        var lockout = new CaltropLockout { MaxFailures = 3, LockFor = TimeSpan.FromMinutes(15), SlowDown = false, Clock = _clock };
        lockout.RecordFailure("erin");
        lockout.RecordFailure("erin");
        _clock.Advance(TimeSpan.FromMinutes(16));

        lockout.RecordFailure("erin");

        Assert.False(lockout.IsLockedOut("erin"));
    }

    [Fact]
    public void Names_ignore_case_so_Admin_and_admin_share_a_counter()
    {
        var lockout = new CaltropLockout { MaxFailures = 2, SlowDown = false, Clock = _clock };
        lockout.RecordFailure("Admin");
        lockout.RecordFailure("ADMIN");

        Assert.True(lockout.IsLockedOut("admin"));
    }

    [Fact]
    public void Reset_unlocks_a_name()
    {
        var lockout = new CaltropLockout { MaxFailures = 1, SlowDown = false, Clock = _clock };
        lockout.RecordFailure("frank");

        lockout.Reset("frank");

        Assert.False(lockout.IsLockedOut("frank"));
    }

    [Fact]
    public async Task SlowDown_makes_a_failed_attempt_wait()
    {
        var lockout = new CaltropLockout { MaxFailures = 10 };
        var clock = System.Diagnostics.Stopwatch.StartNew();

        Assert.False(await lockout.TryAsync("grace", () => false));

        Assert.True(clock.Elapsed >= TimeSpan.FromMilliseconds(200), $"waited only {clock.Elapsed.TotalMilliseconds} ms");
    }

    [Fact]
    public void Flooding_with_names_cannot_fill_memory_or_unlock_anyone()
    {
        var lockout = new CaltropLockout { MaxFailures = 2, MaxTracked = 50, SlowDown = false, Clock = _clock };
        lockout.RecordFailure("victim");
        lockout.RecordFailure("victim");

        for (int i = 0; i < 1000; i++)
        {
            lockout.RecordFailure($"attacker-{i}");
        }

        Assert.True(lockout.IsLockedOut("victim"));
        var entries = (System.Collections.ICollection)typeof(CaltropLockout)
            .GetField("_entries", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!
            .GetValue(lockout)!;
        Assert.True(entries.Count <= 51, $"tracking {entries.Count} names");
    }

    [Fact]
    public void Settings_are_checked()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new CaltropLockout { MaxFailures = 0 });
        Assert.Throws<ArgumentOutOfRangeException>(() => new CaltropLockout { LockFor = TimeSpan.Zero });
        Assert.Throws<ArgumentOutOfRangeException>(() => new CaltropLockout { MaxTracked = 0 });
        Assert.Throws<ArgumentException>(() => new CaltropLockout().IsLockedOut(""));
    }
}
