using System.Collections.Concurrent;
using System.Globalization;

/// <summary>
/// Stops password guessing: after too many failed attempts for the same user (or IP address, or anything you choose),
/// that name is locked out for a while, and every failed attempt is made slower. Locking someone out sets off a
/// <see cref="CaltropAlarmKind.TooManyAttempts"/> alarm (see <see cref="Caltrop.Traps"/>).
/// </summary>
/// <example>
/// <code>
/// // Create one and keep it for the life of your app.
/// static readonly CaltropLockout Logins = new() { MaxFailures = 5, LockFor = TimeSpan.FromMinutes(15) };
///
/// if (Logins.IsLockedOut(userName))
///     return $"Too many attempts. Try again in {Logins.TimeLeft(userName).Minutes + 1} minutes.";
///
/// bool ok = Logins.Try(userName, () => Caltrop.Passwords.Verify(password, user.PasswordHash));
/// </code>
/// </example>
/// <remarks>
/// <para>
/// Every setting is yours to choose. Names are compared ignoring case, so "Admin" and "admin" share one counter.
/// Failures are forgotten after a success, or once <see cref="LockFor"/> has passed since the last failure.
/// </para>
/// <para>
/// Counters live in memory, so restarting the app clears them. On a server that is fine. In a local app, an
/// attacker who can restart it can reset them, so there the slow password hashing is your main protection.
/// In web apps use <see cref="TryAsync(string, Func{bool}, CancellationToken)"/>, so the slow-down does not block a thread.
/// </para>
/// </remarks>
public sealed class CaltropLockout
{
    private static readonly TimeSpan s_firstDelay = TimeSpan.FromMilliseconds(250);
    private static readonly TimeSpan s_maxDelay = TimeSpan.FromSeconds(4);

    private readonly ConcurrentDictionary<string, Entry> _entries = new(StringComparer.OrdinalIgnoreCase);
    private readonly int _maxFailures = 5;
    private readonly TimeSpan _lockFor = TimeSpan.FromMinutes(15);
    private readonly int _maxTracked = 100_000;

    /// <summary>How many failed attempts in a row lock a name out. Default 5.</summary>
    public int MaxFailures
    {
        get => _maxFailures;
        init
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(value, 1);
            _maxFailures = value;
        }
    }

    /// <summary>How long a lockout lasts. Default 15 minutes.</summary>
    public TimeSpan LockFor
    {
        get => _lockFor;
        init
        {
            ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(value, TimeSpan.Zero);
            _lockFor = value;
        }
    }

    /// <summary>
    /// If <see langword="true"/> (the default), <see cref="Try(string, Func{bool})"/> waits after each failure:
    /// 0.25 s, then 0.5 s, 1 s, 2 s, up to 4 s. Guessing gets slower and slower, while a person who mistyped once barely notices.
    /// </summary>
    public bool SlowDown { get; init; } = true;

    /// <summary>
    /// The most names to remember at once. Default 100,000. When there are more, names that are not locked out are
    /// forgotten, so an attacker cannot fill up memory by trying millions of names.
    /// </summary>
    public int MaxTracked
    {
        get => _maxTracked;
        init
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(value, 1);
            _maxTracked = value;
        }
    }

    /// <summary>The clock to use. Leave it alone, except in tests.</summary>
    public TimeProvider Clock { get; init; } = TimeProvider.System;

    /// <summary><see langword="true"/> if this name is locked out right now.</summary>
    /// <param name="who">A user name, email, IP address or any other name.</param>
    public bool IsLockedOut(string who) => TimeLeft(who) > TimeSpan.Zero;

    /// <summary>How long until this name may try again. <see cref="TimeSpan.Zero"/> if it is not locked out.</summary>
    /// <param name="who">A user name, email, IP address or any other name.</param>
    public TimeSpan TimeLeft(string who)
    {
        ArgumentException.ThrowIfNullOrEmpty(who);
        if (!_entries.TryGetValue(who, out Entry? entry))
        {
            return TimeSpan.Zero;
        }

        lock (entry)
        {
            TimeSpan left = entry.LockedUntil - Clock.GetUtcNow();
            return left > TimeSpan.Zero ? left : TimeSpan.Zero;
        }
    }

    /// <summary>
    /// Runs a check, such as a password check, unless the name is locked out. Records the result, and after a
    /// failure waits a little (see <see cref="SlowDown"/>).
    /// </summary>
    /// <param name="who">A user name, email, IP address or any other name.</param>
    /// <param name="check">The check. It is not run at all while the name is locked out.</param>
    /// <returns><see langword="true"/> if the check ran and passed. <see langword="false"/> if it failed or the name is locked out.</returns>
    public bool Try(string who, Func<bool> check)
    {
        ArgumentNullException.ThrowIfNull(check);
        if (IsLockedOut(who))
        {
            return false;
        }

        if (check())
        {
            RecordSuccess(who);
            return true;
        }

        TimeSpan delay = RecordFailureCore(who);
        if (delay > TimeSpan.Zero)
        {
            Thread.Sleep(delay);
        }

        return false;
    }

    /// <summary>Like <see cref="Try(string, Func{bool})"/>, but waits without blocking a thread. Use it in web apps.</summary>
    /// <param name="who">A user name, email, IP address or any other name.</param>
    /// <param name="check">The check. It is not run at all while the name is locked out.</param>
    /// <param name="cancellationToken">Cancels the wait after a failure.</param>
    /// <returns><see langword="true"/> if the check ran and passed. <see langword="false"/> if it failed or the name is locked out.</returns>
    public async Task<bool> TryAsync(string who, Func<bool> check, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(check);
        if (IsLockedOut(who))
        {
            return false;
        }

        if (check())
        {
            RecordSuccess(who);
            return true;
        }

        TimeSpan delay = RecordFailureCore(who);
        if (delay > TimeSpan.Zero)
        {
            await Task.Delay(delay, Clock, cancellationToken).ConfigureAwait(false);
        }

        return false;
    }

    /// <summary>Records a failed attempt yourself, if you do not use <see cref="Try(string, Func{bool})"/>. It does not wait.</summary>
    /// <param name="who">A user name, email, IP address or any other name.</param>
    public void RecordFailure(string who) => RecordFailureCore(who);

    /// <summary>Records a successful attempt: the name's failures are forgotten.</summary>
    /// <param name="who">A user name, email, IP address or any other name.</param>
    public void RecordSuccess(string who)
    {
        ArgumentException.ThrowIfNullOrEmpty(who);
        _entries.TryRemove(who, out _);
    }

    /// <summary>Unlocks a name and forgets its failures, for example after an admin checks the account.</summary>
    /// <param name="who">A user name, email, IP address or any other name.</param>
    public void Reset(string who) => RecordSuccess(who);

    private TimeSpan RecordFailureCore(string who)
    {
        ArgumentException.ThrowIfNullOrEmpty(who);
        if (_entries.Count >= MaxTracked)
        {
            ForgetUnlocked();
        }

        Entry entry = _entries.GetOrAdd(who, static _ => new Entry());
        DateTimeOffset now = Clock.GetUtcNow();
        bool lockedNow = false;
        int failures;
        lock (entry)
        {
            if (entry.LockedUntil > now)
            {
                return TimeSpan.Zero; // already locked out
            }

            if (entry.Failures > 0 && now - entry.LastFailure >= LockFor)
            {
                entry.Failures = 0; // old failures are forgotten
            }

            entry.Failures++;
            entry.LastFailure = now;
            failures = entry.Failures;
            if (failures >= MaxFailures)
            {
                entry.LockedUntil = now + LockFor;
                entry.Failures = 0;
                lockedNow = true;
            }
        }

        if (lockedNow)
        {
            Caltrop.Traps.Raise(
                CaltropAlarmKind.TooManyAttempts,
                "Lockout",
                $"Too many failed attempts for \"{who}\": locked out for {Describe(LockFor)}.",
                who);
        }

        return SlowDown ? Delay(failures) : TimeSpan.Zero;
    }

    private static TimeSpan Delay(int failures)
    {
        double milliseconds = s_firstDelay.TotalMilliseconds * Math.Pow(2, Math.Min(failures - 1, 16));
        return TimeSpan.FromMilliseconds(Math.Min(milliseconds, s_maxDelay.TotalMilliseconds));
    }

    private void ForgetUnlocked()
    {
        DateTimeOffset now = Clock.GetUtcNow();
        foreach (KeyValuePair<string, Entry> pair in _entries)
        {
            bool locked;
            lock (pair.Value)
            {
                locked = pair.Value.LockedUntil > now;
            }

            if (!locked)
            {
                _entries.TryRemove(pair);
            }
        }
    }

    private static string Describe(TimeSpan span)
    {
        (double amount, string unit) = span.TotalMinutes >= 1 ? (span.TotalMinutes, "minute") : (span.TotalSeconds, "second");
        string number = amount.ToString("0.#", CultureInfo.InvariantCulture);
        return number == "1" ? $"1 {unit}" : $"{number} {unit}s";
    }

    private sealed class Entry
    {
        public int Failures { get; set; }

        public DateTimeOffset LastFailure { get; set; }

        public DateTimeOffset LockedUntil { get; set; }
    }
}
