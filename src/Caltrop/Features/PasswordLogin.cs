using System.Globalization;
using System.Security.Cryptography;
using CaltropSecurity.Internal;

public static partial class Caltrop
{
    public static partial class Passwords
    {
        /// <summary>
        /// Checked when there is no such user, so the answer takes just as long. It is made of random bytes (not by
        /// hashing), so making it costs nothing and the first unknown user is not slower than the rest.
        /// </summary>
        private static readonly string s_dummyHash = Format(PasswordKdf.DefaultIterations, RandomNumberGenerator.GetBytes(PasswordKdf.SaltSize), RandomNumberGenerator.GetBytes(HashSize));
        private static CaltropPasswordRules s_rules = CaltropPasswordRules.Default;
        private static CaltropLockout s_lockout = new();

        /// <summary>The rules <see cref="Create(string, string[])"/> uses. Default: <see cref="CaltropPasswordRules.Default"/>.</summary>
        /// <example><code>Caltrop.Passwords.Rules = new CaltropPasswordRules { MinLength = 8 };</code></example>
        public static CaltropPasswordRules Rules
        {
            get => Volatile.Read(ref s_rules);
            set => Volatile.Write(ref s_rules, value ?? throw new ArgumentNullException(nameof(value)));
        }

        /// <summary>
        /// The lockout <see cref="LogIn(string, string, string?)"/> uses. Default: 5 failed attempts lock a user out
        /// for 15 minutes, and every failed attempt is slowed down.
        /// </summary>
        /// <example><code>Caltrop.Passwords.Lockout = new CaltropLockout { MaxFailures = 10, LockFor = TimeSpan.FromMinutes(5) };</code></example>
        public static CaltropLockout Lockout
        {
            get => Volatile.Read(ref s_lockout);
            set => Volatile.Write(ref s_lockout, value ?? throw new ArgumentNullException(nameof(value)));
        }

        /// <summary>
        /// Everything for a new password, in one call: checks it is strong enough (see <see cref="Rules"/>), and if so,
        /// hashes it. Use it when someone signs up or changes their password.
        /// </summary>
        /// <param name="password">The new password.</param>
        /// <param name="relatedWords">Words it must not contain, such as the user's name and email.</param>
        /// <returns>The result: store <see cref="CaltropNewPassword.Hash"/> if it is <see cref="CaltropNewPassword.Ok"/>, otherwise show <see cref="CaltropNewPassword.Message"/>.</returns>
        /// <example>
        /// <code>
        /// var result = Caltrop.Passwords.Create(password, user.Name, user.Email);
        /// if (!result.Ok) return result.Message;      // "Use at least 12 characters."
        /// user.PasswordHash = result.Hash;
        /// </code>
        /// </example>
        public static CaltropNewPassword Create(string password, params string[] relatedWords)
        {
            CaltropPasswordCheck check = Check(password, Rules, relatedWords);
            return new CaltropNewPassword(check.Ok ? Hash(password) : null, check);
        }

        /// <summary>
        /// Everything for a login, in one call. It checks the password, locks the user out after too many failures
        /// (see <see cref="Lockout"/>), slows down guessing, takes the same time whether or not the user exists, sets
        /// off the alarm for decoy accounts, and upgrades old hashes.
        /// </summary>
        /// <param name="user">The user name or email they typed. Used for the lockout, not stored.</param>
        /// <param name="password">The password they typed.</param>
        /// <param name="storedHash">That user's stored hash, or <see langword="null"/> if there is no such user.</param>
        /// <returns>The result: let them in if <see cref="CaltropLogin.Ok"/>, otherwise show <see cref="CaltropLogin.Message"/>.</returns>
        /// <example>
        /// <code>
        /// var login = Caltrop.Passwords.LogIn(email, password, user?.PasswordHash);
        /// if (!login.Ok) return login.Message;          // "Wrong user name or password."
        /// if (login.NewHash is not null) user.PasswordHash = login.NewHash;
        /// </code>
        /// </example>
        /// <remarks>After a failed attempt it waits a little before returning. In web apps use <see cref="LogInAsync(string, string, string?, CancellationToken)"/>.</remarks>
        public static CaltropLogin LogIn(string user, string password, string? storedHash)
        {
            ArgumentException.ThrowIfNullOrEmpty(user);
            ArgumentNullException.ThrowIfNull(password);
            CaltropLockout lockout = Lockout;
            bool ok = lockout.Try(user, () => VerifyOrDummy(password, storedHash)); // not even run while the user is locked out
            return Finish(lockout, user, password, storedHash, ok);
        }

        /// <summary>Like <see cref="LogIn(string, string, string?)"/>, but waits after a failed attempt without blocking a thread. Use it in web apps.</summary>
        /// <param name="user">The user name or email they typed. Used for the lockout, not stored.</param>
        /// <param name="password">The password they typed.</param>
        /// <param name="storedHash">That user's stored hash, or <see langword="null"/> if there is no such user.</param>
        /// <param name="cancellationToken">Cancels the wait after a failed attempt.</param>
        /// <returns>The result: let them in if <see cref="CaltropLogin.Ok"/>, otherwise show <see cref="CaltropLogin.Message"/>.</returns>
        public static async Task<CaltropLogin> LogInAsync(string user, string password, string? storedHash, CancellationToken cancellationToken = default)
        {
            ArgumentException.ThrowIfNullOrEmpty(user);
            ArgumentNullException.ThrowIfNull(password);
            CaltropLockout lockout = Lockout;
            bool ok = await lockout.TryAsync(user, () => VerifyOrDummy(password, storedHash), cancellationToken).ConfigureAwait(false);
            return Finish(lockout, user, password, storedHash, ok);
        }

        private static CaltropLogin Finish(CaltropLockout lockout, string user, string password, string? storedHash, bool ok)
        {
            if (ok)
            {
                string? newHash = NeedsRehash(storedHash!) ? Hash(password) : null;
                return new CaltropLogin(true, "Logged in.", lockedOut: false, TimeSpan.Zero, newHash);
            }

            TimeSpan wait = lockout.TimeLeft(user);
            return wait > TimeSpan.Zero ? CaltropLogin.ForLockout(wait) : new CaltropLogin(false, "Wrong user name or password.", lockedOut: false, TimeSpan.Zero, null);
        }

        /// <summary>Checks against a dummy hash when there is no such user, so the answer takes just as long and does not reveal who has an account.</summary>
        private static bool VerifyOrDummy(string password, string? storedHash)
        {
            if (storedHash is null)
            {
                Verify(password, s_dummyHash);
                return false;
            }

            return Verify(password, storedHash);
        }
    }
}

/// <summary>The result of <see cref="Caltrop.Passwords.Create(string, string[])"/>.</summary>
public sealed class CaltropNewPassword
{
    internal CaltropNewPassword(string? hash, CaltropPasswordCheck check)
    {
        Hash = hash;
        Check = check;
    }

    /// <summary><see langword="true"/> if the password is strong enough. Then store <see cref="Hash"/>.</summary>
    public bool Ok => Hash is not null;

    /// <summary>The hash to store for the user, or <see langword="null"/> if the password was not accepted.</summary>
    public string? Hash { get; }

    /// <summary>What to tell the user if the password was not accepted, such as "Use at least 12 characters." Empty when <see cref="Ok"/>.</summary>
    public string Message => Ok ? string.Empty : string.Join(" ", Check.Problems);

    /// <summary>"Very weak", "Weak", "Fair", "Strong" or "Very strong".</summary>
    public string Strength => Check.Strength;

    /// <summary>The full strength check.</summary>
    public CaltropPasswordCheck Check { get; }

    /// <summary>Returns <see cref="Message"/>, or "OK".</summary>
    public override string ToString() => Ok ? "OK" : Message;
}

/// <summary>The result of <see cref="Caltrop.Passwords.LogIn(string, string, string?)"/>.</summary>
public sealed class CaltropLogin
{
    internal CaltropLogin(bool ok, string message, bool lockedOut, TimeSpan tryAgainIn, string? newHash)
    {
        Ok = ok;
        Message = message;
        LockedOut = lockedOut;
        TryAgainIn = tryAgainIn;
        NewHash = newHash;
    }

    /// <summary><see langword="true"/> if the password is right: let them in.</summary>
    public bool Ok { get; }

    /// <summary>
    /// What to tell the user: "Logged in.", "Wrong user name or password." (it never says which was wrong), or
    /// "Too many attempts. Try again in 15 minutes."
    /// </summary>
    public string Message { get; }

    /// <summary><see langword="true"/> if the user is locked out after too many failed attempts.</summary>
    public bool LockedOut { get; }

    /// <summary>How long until a locked-out user may try again.</summary>
    public TimeSpan TryAgainIn { get; }

    /// <summary>A better hash for the same password, when the stored one is out of date. If it is not <see langword="null"/>, store it.</summary>
    public string? NewHash { get; }

    /// <summary>Returns <see cref="Message"/>.</summary>
    public override string ToString() => Message;

    internal static CaltropLogin ForLockout(TimeSpan wait)
    {
        string when = wait.TotalSeconds < 60
            ? $"{Math.Max(1, (int)Math.Ceiling(wait.TotalSeconds)).ToString(CultureInfo.InvariantCulture)} seconds"
            : (int)Math.Ceiling(wait.TotalMinutes) == 1 ? "1 minute" : $"{((int)Math.Ceiling(wait.TotalMinutes)).ToString(CultureInfo.InvariantCulture)} minutes";
        return new CaltropLogin(false, $"Too many attempts. Try again in {when}.", lockedOut: true, wait, null);
    }
}
