using System.Diagnostics.CodeAnalysis;
using CaltropSecurity.Internal;

public static partial class Caltrop
{
    /// <summary>
    /// The trap system. When someone tries to get around Caltrop (uses a decoy, guesses passwords, changes data or
    /// files), a trap goes off: Caltrop raises <see cref="Alarm"/> so your app can react, and, if you choose, locks
    /// itself down and wipes its keys from memory.
    /// </summary>
    /// <example>
    /// <code>
    /// // When your app starts:
    /// Caltrop.Traps.Alarm += (_, alarm) => logger.LogCritical("Caltrop alarm: {Alarm}", alarm);
    /// Caltrop.Traps.LockDownOn = CaltropAlarmKind.DecoyUsed;   // optional: wipe keys and stop if a decoy is used
    /// </code>
    /// </example>
    /// <remarks>
    /// Everything is off until you turn it on: with no handler and <see cref="LockDownOn"/> left at
    /// <see cref="CaltropAlarmKind.None"/>, alarms change nothing. Caltrop works fully offline, so it never sends
    /// alerts anywhere by itself: your handler decides what happens (log it, block the user, email someone).
    /// </remarks>
    public static class Traps
    {
        private static int s_lockDownOn;
        private static int s_lockedDown;
        private static CaltropAlarm? s_lockedDownBy;
        private static CaltropLog? s_log;

        [ThreadStatic]
        private static bool t_notifying;

        /// <summary>
        /// Raised every time a trap goes off, on the thread that tripped it. Keep handlers quick. If a handler throws,
        /// the exception is ignored, so a broken handler can never stop a trap from working.
        /// </summary>
        /// <remarks>
        /// A handler can use Caltrop. If it sets off another alarm itself (for example by reading a vault that was
        /// tampered with), that alarm is recorded, and can still lock Caltrop down, but does not call the handlers
        /// again, so a handler can never end up calling itself forever.
        /// </remarks>
        public static event EventHandler<CaltropAlarm>? Alarm;

        /// <summary>
        /// Which kinds of alarm make Caltrop lock itself down: wipe every key, key pair, vault and log key from memory,
        /// remove <c>CALTROP_KEY</c> from this process's environment, and refuse to work until the app restarts.
        /// Default: <see cref="CaltropAlarmKind.None"/>.
        /// </summary>
        /// <remarks>
        /// On a server, only lock down on <see cref="CaltropAlarmKind.DecoyUsed"/>. Anyone on the internet can make
        /// failed logins or send damaged data, so locking down on <see cref="CaltropAlarmKind.TooManyAttempts"/> or
        /// <see cref="CaltropAlarmKind.Tampering"/> would let an attacker switch your app off on purpose. Those are
        /// meant for local apps and tools, where an attack on them means the device itself is in the wrong hands.
        /// </remarks>
        public static CaltropAlarmKind LockDownOn
        {
            get => (CaltropAlarmKind)Volatile.Read(ref s_lockDownOn);
            set
            {
                if ((value & ~CaltropAlarmKind.All) != 0)
                {
                    throw new ArgumentOutOfRangeException(nameof(value), value, "Unknown alarm kind.");
                }

                Volatile.Write(ref s_lockDownOn, (int)value);
            }
        }

        /// <summary>
        /// Where alarms are recorded, before anything else happens. If you leave it <see langword="null"/>, alarms go
        /// to Caltrop's own log (see <see cref="Caltrop.Log(string)"/>), when it has a <see cref="Caltrop.Folder"/>.
        /// </summary>
        public static CaltropLog? Log
        {
            get => Volatile.Read(ref s_log);
            set => Volatile.Write(ref s_log, value);
        }

        /// <summary><see langword="true"/> once Caltrop has locked itself down. Only restarting the app clears it.</summary>
        public static bool IsLockedDown => Volatile.Read(ref s_lockedDown) != 0;

        /// <summary>How many handlers are listening for alarms. (For <see cref="Status"/>.)</summary>
        internal static int HandlerCount => Alarm?.GetInvocationList().Length ?? 0;

        /// <summary>The alarm that caused the lockdown, or <see langword="null"/> if Caltrop is not locked down.</summary>
        public static CaltropAlarm? LockedDownBy => IsLockedDown ? Volatile.Read(ref s_lockedDownBy) : null;

        /// <summary>
        /// Locks Caltrop down now, whatever <see cref="LockDownOn"/> says: raises an alarm, wipes every key from
        /// memory and makes Caltrop refuse to work until the app restarts. There is deliberately no way to undo it.
        /// </summary>
        /// <param name="reason">Why, for the alarm and the log. For example <c>"Debugger attached"</c>.</param>
        public static void LockDown(string reason)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(reason);
            Raise(CaltropAlarmKind.Custom, "Lockdown", $"Caltrop was locked down: {reason}", subject: null, forceLockDown: true);
        }

        /// <summary>
        /// Sets off a trap of your own, for example when someone opens a fake admin page. It raises
        /// <see cref="Alarm"/> with <see cref="CaltropAlarmKind.Custom"/>, and locks Caltrop down if
        /// <see cref="LockDownOn"/> includes <see cref="CaltropAlarmKind.Custom"/>.
        /// </summary>
        /// <param name="trap">A short name for your trap, such as <c>"Fake admin page"</c>.</param>
        /// <param name="subject">Optional. Who or what set it off, such as an IP address or user name.</param>
        public static void Trigger(string trap, string? subject = null)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(trap);
            string by = subject is null ? string.Empty : $" by {subject}";
            Raise(CaltropAlarmKind.Custom, trap, $"Trap \"{trap}\" was set off{by}.", subject);
        }

        /// <summary>Records, locks down if configured, then notifies. Never throws.</summary>
        internal static void Raise(CaltropAlarmKind kind, string trap, string message, string? subject, bool forceLockDown = false)
        {
            bool lockDown = forceLockDown || (LockDownOn & kind) != 0;
            var alarm = new CaltropAlarm(kind, trap, message, subject, DateTimeOffset.UtcNow, lockDown && !IsLockedDown);

            // 1. Record it first, while the log key still exists.
            CaltropLog? log = IsLockedDown ? null : Log ?? Home.TryLog();
            if (log is not null && !IsLockedDown)
            {
                try
                {
                    log.Write(alarm.ToString());
                }
#pragma warning disable CA1031 // A failing log must never stop the trap.
                catch (Exception)
#pragma warning restore CA1031
                {
                }
            }

            // 2. Lock down before anyone else gets a chance to use the keys.
            if (lockDown)
            {
                EnterLockDown(alarm);
            }

            // 3. Tell the app, unless this alarm went off inside a handler (see Alarm).
            if (!t_notifying && Alarm is { } handlers)
            {
                t_notifying = true;
                try
                {
                    foreach (Delegate handler in handlers.GetInvocationList())
                    {
                        try
                        {
                            ((EventHandler<CaltropAlarm>)handler)(null, alarm);
                        }
#pragma warning disable CA1031 // A broken handler must never stop the trap or the operation that tripped it.
                        catch (Exception)
#pragma warning restore CA1031
                        {
                        }
                    }
                }
                finally
                {
                    t_notifying = false;
                }
            }
        }

        /// <summary>Throws <see cref="CaltropErrorCode.LockedDown"/> if Caltrop is locked down.</summary>
        internal static void ThrowIfLockedDown()
        {
            if (Volatile.Read(ref s_lockedDown) != 0)
            {
                throw LockedDownError();
            }
        }

        /// <summary>
        /// Call after an operation has read key material and before returning its result. If a lockdown wiped the
        /// key while it was being read, the result may be made with a partly zeroed key, so it must not escape.
        /// </summary>
        internal static void ThrowIfLockedDownAfterUse()
        {
            Interlocked.MemoryBarrier();
            ThrowIfLockedDown();
        }

        /// <summary>Clears every trap setting and the lockdown (tests only).</summary>
        internal static void ResetForTests()
        {
            Alarm = null;
            Volatile.Write(ref s_lockDownOn, 0);
            Volatile.Write(ref s_log, null);
            Volatile.Write(ref s_lockedDownBy, null);
            Volatile.Write(ref s_lockedDown, 0);
        }

        private static void EnterLockDown(CaltropAlarm alarm)
        {
            if (Interlocked.CompareExchange(ref s_lockedDownBy, alarm, null) is not null)
            {
                return; // already locked down
            }

            // The flag goes up before anything is wiped (see ThrowIfLockedDownAfterUse).
            Interlocked.Exchange(ref s_lockedDown, 1);
            Wipeables.WipeAll();
            Environment.SetEnvironmentVariable(KeyEnvironmentVariable, null); // this process's copy only
        }

        private static CaltropException LockedDownError()
        {
            CaltropAlarm? by = Volatile.Read(ref s_lockedDownBy);
            string why = by is null ? "a trap went off" : $"a trap went off ({by.Trap}: {by.Message})";
            return new CaltropException(
                CaltropErrorCode.LockedDown,
                $"Caltrop has locked itself down because {why}. Its keys have been wiped from memory. Restart the app to use Caltrop again.");
        }
    }
}

/// <summary>Details of a trap that went off. Passed to <see cref="Caltrop.Traps.Alarm"/>.</summary>
[SuppressMessage("Naming", "CA1710:Identifiers should have correct suffix", Justification = "It is an alarm first; \"CaltropAlarmEventArgs\" would be harder to read.")]
public sealed class CaltropAlarm : EventArgs
{
    internal CaltropAlarm(CaltropAlarmKind kind, string trap, string message, string? subject, DateTimeOffset time, bool causedLockDown)
    {
        Kind = kind;
        Trap = trap;
        Message = message;
        Subject = subject;
        Time = time;
        CausedLockDown = causedLockDown;
    }

    /// <summary>What kind of attack this looks like.</summary>
    public CaltropAlarmKind Kind { get; }

    /// <summary>Which trap went off, for example <c>"Decoy password"</c> or <c>"Lockout"</c>.</summary>
    public string Trap { get; }

    /// <summary>A sentence describing what happened.</summary>
    /// <remarks>It can contain text from the attacker (such as a user name), so encode it before showing it in HTML.</remarks>
    public string Message { get; }

    /// <summary>Who or what set it off, when known: a user name, a file path, a decoy's label. Can come from the attacker.</summary>
    public string? Subject { get; }

    /// <summary>When it happened (UTC).</summary>
    public DateTimeOffset Time { get; }

    /// <summary><see langword="true"/> if this alarm made Caltrop lock itself down.</summary>
    public bool CausedLockDown { get; }

    /// <summary>Returns <c>[Kind] Message</c>, plus a note if it caused a lockdown.</summary>
    public override string ToString() => CausedLockDown ? $"[{Kind}] {Message} Caltrop locked itself down." : $"[{Kind}] {Message}";
}

/// <summary>The kinds of alarm. Combine them with <c>|</c> for <see cref="Caltrop.Traps.LockDownOn"/>.</summary>
[Flags]
public enum CaltropAlarmKind
{
    /// <summary>No alarms.</summary>
    None = 0,

    /// <summary>A decoy was used: a fake password hash, API key, encrypted value or watched value. See <see cref="Caltrop.Decoys"/>.</summary>
    DecoyUsed = 1,

    /// <summary>Too many failed attempts locked someone out. See <see cref="CaltropLockout"/>.</summary>
    TooManyAttempts = 2,

    /// <summary>Data, a file, a folder, a log or Caltrop.dll itself was changed. See <see cref="Caltrop.Tamper"/>.</summary>
    Tampering = 4,

    /// <summary>One of your own traps, set off with <see cref="Caltrop.Traps.Trigger(string, string?)"/>.</summary>
    Custom = 8,

    /// <summary>Every kind of alarm.</summary>
    All = DecoyUsed | TooManyAttempts | Tampering | Custom,
}
