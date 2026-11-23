# Caltrop guide

Everything Caltrop does, with examples. For a quick overview see the [README](../README.md).

- [Setup](#setup): [Caltrop's key](#caltrops-key), [Caltrop's folder](#caltrops-folder)
- [Encrypting data](#encrypting-data)
- [Key rotation](#key-rotation)
- [Password encryption](#password-encryption)
- [User passwords](#user-passwords)
- [Vault](#vault)
- [Traps](#traps): [alarms and lockdown](#alarms-and-lockdown), [decoys](#decoys), [lockout](#lockout),
  [tamper checks](#tamper-checks)
- [Tamper-proof log](#tamper-proof-log)
- [Safe input](#safe-input)
- [Tokens](#tokens)
- [Files and streams](#files-and-streams)
- [Public keys and signatures](#public-keys-and-signatures)
- [API keys](#api-keys)
- [Webhooks](#webhooks)
- [Hashing and searching encrypted data](#hashing-and-searching-encrypted-data)
- [Random values](#random-values)
- [Errors and troubleshooting](#errors-and-troubleshooting)
- [Performance and thread safety](#performance-and-thread-safety)

## Setup

1. Download `Caltrop.dll` and add it to your project, as the [README](../README.md#add-it-to-your-project) shows.
2. Start using it. There is nothing else to set up.

Caltrop needs .NET 10 or later and works fully offline. Its types have no namespace, so no `using` line is
needed.

### Caltrop's key

Everything that does not take a key (`Caltrop.Encrypt(text)`, `Caltrop.Secrets`, `Caltrop.Log`, tokens, decoys,
seals) uses `Caltrop.DefaultKeys`. The first time a key is needed, Caltrop looks in this order:

1. A key you set in code with `Caltrop.UseKey(key)` (or `Caltrop.UseKeys(ring)`).
2. The `CALTROP_KEY` environment variable.
3. Its own key file, `caltrop.key` in [Caltrop's folder](#caltrops-folder). If there is none, Caltrop makes a new
   key and saves it there.

On your own computer, and for desktop apps and tools, it just works.

**Back up `caltrop.key`.** If it is lost, everything encrypted with it is lost too. To read the same data on
another computer, copy `caltrop.key` into the same folder there.

**Servers and containers.** Every copy of your app must use the same key, so set `CALTROP_KEY` on each one:

```csharp
Console.WriteLine(CaltropKey.Generate().Export());   // run once, and put the output in CALTROP_KEY
```

Inside a container, Caltrop never makes a key of its own, because the container's disk is thrown away with it.
It asks you to set `CALTROP_KEY` instead, or `CALTROP_FOLDER` pointing at a volume that is kept. `Caltrop.Secrets`
and `Caltrop.Log` need `CALTROP_FOLDER` in a container too, for the same reason.

### Caltrop's folder

| System | Folder |
| --- | --- |
| Windows | `%LOCALAPPDATA%\Caltrop\<YourApp>` |
| macOS | `~/Library/Application Support/Caltrop/<YourApp>` |
| Linux | `~/.local/share/Caltrop/<YourApp>` |

| File | What it is |
| --- | --- |
| `caltrop.key` | The key. Back it up and keep it secret. It can hold several keys, newest first, separated by commas, for [rotation](#key-rotation). |
| `secrets.vault` | [`Caltrop.Secrets`](#vault), encrypted with the key. |
| `caltrop.log` | [Caltrop's tamper-proof log](#tamper-proof-log), including every alarm. |
| `README.txt` | A note explaining these files to whoever finds the folder. |
| `*.lock` | Empty files that let several copies of your app use the vault and the log at once. Leave them. |

On Linux and macOS, only your user account can read the folder and its files. On Windows, the user's app data
folder is already private to the user.

Several copies of your app can use the folder at the same time (two windows of a desktop app, or several
servers sharing `CALTROP_FOLDER`): they take turns on the files, so no secret and no log entry is lost, and each
copy sees the others' changes. Copies that start at the same moment still agree on one key.

If Caltrop cannot create its folder, for example because a service account has no app data folder it can write
to, the error says so and what to set instead.

To keep these files somewhere else, set the `CALTROP_FOLDER` environment variable, or `Caltrop.Folder = "..."`
when your app starts. `Caltrop.Folder = null` stops Caltrop keeping any files at all; then give it a key with
`CALTROP_KEY` or `Caltrop.UseKey`.

### Making your own keys

```csharp
using var key = CaltropKey.Generate();
Console.WriteLine(key.Export());   // ctk_... (52 characters)
```

Store the exported text in a secret manager or an environment variable, never in source control. Load it with
`CaltropKey.Parse(text)`, which also accepts 32 random bytes as Base64 or hex, so keys made with
`openssl rand -base64 32` work too. Every method that uses a key also has an overload that takes one:
`Caltrop.Encrypt(text, key)`.

Each key has a short public `Id` (8 hex characters). It is stored with everything the key encrypts, so error
messages can tell you which key was expected. `key.ToString()` shows only the id, so logging a key is safe.

To use keys from your app's configuration in ASP.NET Core:

```csharp
var builder = WebApplication.CreateBuilder(args);
Caltrop.UseKeys(CaltropKeyRing.Parse(builder.Configuration["Caltrop:Keys"]!));
```

Caltrop keeps using the key objects you pass, so do not dispose them while they are the default.

## Encrypting data

```csharp
string encrypted = Caltrop.Encrypt("4111 1111 1111 1111", key);
string original  = Caltrop.Decrypt(encrypted, key);

byte[] encryptedBytes = Caltrop.Encrypt(fileBytes, key);
byte[] originalBytes  = Caltrop.Decrypt(encryptedBytes, key);
```

Text results are Base64Url (letters, digits, `-` and `_`), safe for databases, JSON, URLs and cookies.
Encrypting the same value twice gives different results, so nobody can tell that two rows hold the same value.

### Context

Pass a context to tie a value to where it belongs:

```csharp
string encrypted = Caltrop.Encrypt(user.Ssn, key, context: $"users.ssn:{user.Id}");
string ssn       = Caltrop.Decrypt(encrypted, key, context: $"users.ssn:{user.Id}");
```

If someone with database access copies an encrypted value into another row or column, it will not decrypt
there. The context is not stored, and it does not need to be secret.

### Entity Framework Core

A value converter encrypts a column transparently:

```csharp
protected override void OnModelCreating(ModelBuilder modelBuilder)
{
    modelBuilder.Entity<Customer>()
        .Property(c => c.TaxId)
        .HasConversion(v => Caltrop.Encrypt(v), v => Caltrop.Decrypt(v));
}
```

Converters are expression trees, which cannot use optional arguments. Use the default-key overloads as above,
or pass every argument: `v => Caltrop.Encrypt(v, Keys.Primary, null)`.

### How big is the output?

| Method | Extra bytes |
| --- | --- |
| `Encrypt` with a key | 46 |
| `EncryptWithPassword` | 50 |
| `Encrypt` with a public key | 87 |
| `Tokens.Create` | 62 |
| `Files` | 30, plus 16 per 64 KiB |

Text output is Base64Url, so it is about 4/3 of the bytes: a value of *n* UTF-8 bytes encrypted with a key
becomes ⌈4 × (*n* + 46) / 3⌉ characters. Make database columns big enough. A cut-off value cannot be decrypted.

## Key rotation

A `CaltropKeyRing` holds several keys, newest first. New data uses the newest key (`Primary`), and decryption
picks whichever key the data was made with.

1. Generate a new key and put it **first**: `CALTROP_KEY="ctk_new...,ctk_old..."`.
2. Deploy. New data now uses the new key; old data still decrypts.
3. Optionally re-encrypt old data: `Caltrop.Encrypt(Caltrop.Decrypt(value, ring), ring.Primary)`.
4. Once nothing uses the old key, remove it from the ring.

```csharp
var ring = CaltropKeyRing.Parse(Environment.GetEnvironmentVariable("CALTROP_KEY")!);
string encrypted = Caltrop.Encrypt("data", ring.Primary);
string decrypted = Caltrop.Decrypt(encrypted, ring);
```

Tokens and files support rings the same way.

## Password encryption

When there is no key, only a password:

```csharp
string encrypted = Caltrop.EncryptWithPassword("my notes", password);
string notes     = Caltrop.DecryptWithPassword(encrypted, password);
```

The key is derived with PBKDF2-HMAC-SHA256 and 600,000 iterations, which takes a noticeable fraction of a
second by design. Security depends on the password: a short or common one can be guessed. For anything your
server encrypts, use a `CaltropKey` instead.

### Wallet secrets

Password encryption suits crypto wallet seed phrases and private keys, where the user's password is the only
key:

```csharp
byte[] locked = Caltrop.EncryptWithPassword(privateKey, password);   // store this

byte[] unlocked = Caltrop.DecryptWithPassword(locked, password);      // when the user unlocks the wallet
try
{
    // sign with unlocked
}
finally
{
    CryptographicOperations.ZeroMemory(unlocked);   // wipe it from memory when done
}
```

- Prefer the `byte[]` overloads for secrets, so you can wipe them after use. .NET strings can't be wiped.
- Anyone who copies the encrypted wallet can try passwords offline, with no limit on attempts. Caltrop makes
  each guess slow, but a short or common password will still be found. Ask for a long passphrase.
- A wrong password and a damaged file both throw a `CaltropException` with `AuthenticationFailed`. Caltrop
  never returns a wrong seed phrase.
- Caltrop doesn't create wallets, derive addresses or sign blockchain transactions. Bitcoin and Ethereum use
  the secp256k1 curve, which Caltrop doesn't include. Use a dedicated library such as NBitcoin or Nethereum
  for those, and Caltrop to keep the keys safe at rest.

## User passwords

Never store or encrypt user passwords. Two calls handle everything:

```csharp
// Sign-up, or a password change
CaltropNewPassword result = Caltrop.Passwords.Create(password, user.Name, user.Email);
if (!result.Ok)
{
    return result.Message;   // "Use at least 12 characters. This is one of the most common passwords..."
}

user.PasswordHash = result.Hash;

// Login
CaltropLogin login = Caltrop.Passwords.LogIn(email, password, user?.PasswordHash);   // null if no such user
if (!login.Ok)
{
    return login.Message;   // "Wrong user name or password." or "Too many attempts. Try again in 15 minutes."
}

if (login.NewHash is not null)
{
    user.PasswordHash = login.NewHash;   // an old hash was upgraded
}
```

`Create` checks the password (see [checking new passwords](#checking-new-passwords)) and hashes it. `LogIn`:

- checks the password against the stored hash;
- locks a user out after 5 failed attempts in a row, for 15 minutes ([lockout](#lockout)), and does not even check
  passwords while they are locked out;
- waits a little longer after each failed attempt, so guessing is slow;
- takes just as long when the user does not exist, and gives the same message, so nobody can find out who has an
  account;
- sets off the alarm if someone tries to log in to a [decoy](#decoys) account;
- gives you a `NewHash` when the stored hash uses older settings, so hashes upgrade as people log in.

In web apps, use `await Caltrop.Passwords.LogInAsync(...)`, so the waiting does not block a thread. To change the
rules:

```csharp
Caltrop.Passwords.Rules = new CaltropPasswordRules { MinLength = 10 };
Caltrop.Passwords.Lockout = new CaltropLockout { MaxFailures = 10, LockFor = TimeSpan.FromMinutes(5) };
```

### Step by step

`Create` and `LogIn` are built on these, which you can use directly:

```csharp
user.PasswordHash = Caltrop.Passwords.Hash(password);
bool ok = Caltrop.Passwords.Verify(password, user.PasswordHash);
bool upgrade = Caltrop.Passwords.NeedsRehash(user.PasswordHash);
```

Hashes use the standard PHC format (`$pbkdf2-sha256$i=600000$salt$hash`), so other tools can read them.
Passwords are Unicode-normalized first, so `é` typed on a Mac and on Windows matches.

### Checking new passwords

`Passwords.Check` tells you whether a new password is good enough, fully offline. It rejects the 10,000 most
common passwords and their look-alikes (`P@ssw0rd!`, `Password123`), repeats and sequences (`aaaa`, `abcd`,
`qwerty`), and passwords built from words you pass in, such as the user's name or email:

```csharp
CaltropPasswordCheck check = Caltrop.Passwords.Check(newPassword, user.Name, user.Email, "MyApp");
if (!check.Ok)
{
    return string.Join(" ", check.Problems);   // sentences you can show the user
}

Console.WriteLine(check.Strength);   // "Very weak", "Weak", "Fair", "Strong" or "Very strong"
```

The default rules ask for at least 12 characters and a score of at least 3 (out of 4). Set your own:

```csharp
var rules = new CaltropPasswordRules { MinLength = 16, MinScore = 4, BlockCommon = true };
var check = Caltrop.Passwords.Check(newPassword, rules, user.Email);
```

The score is an estimate of how hard the password is to guess. Long passphrases of random words score well.

## Vault

The quickest way to keep secrets is `Caltrop.Secrets`, with nothing to set up. It stores them encrypted in
`secrets.vault` in [Caltrop's folder](#caltrops-folder), locked with Caltrop's key:

```csharp
Caltrop.Secrets.Set("db-password", "hunter2");
string? db = Caltrop.Secrets.Get("db-password");
Caltrop.Secrets.Remove("old-secret");
IReadOnlyList<string> names = Caltrop.Secrets.Names;
```

For a vault in a file you choose, or locked with a password (for example a password manager's master
password), use `CaltropVault`:

```csharp
using (var vault = CaltropVault.Create("secrets.vault", masterPassword))   // or Create(path, key)
{
    vault.Set("db-password", "hunter2");
    vault.Set("signing-key", keyBytes);
}

using var opened = CaltropVault.Open("secrets.vault", masterPassword);
string? db = opened.Get("db-password");
byte[]? signingKey = opened.GetBytes("signing-key");
opened.Remove("old-secret");
opened.ChangePassword(newMasterPassword);
```

- Every change is saved straight away, through a temporary file, so a crash never leaves a broken vault.
- Several programs can use the same vault at once. Each sees the others' changes, and no change is lost. If one
  of them changes the password, the others are told to open it again with the new one.
- With a password, a wrong password and a changed file give the same `AuthenticationFailed` error. With a key,
  a changed file also sets off a tampering alarm.
- Secrets stay in memory while the vault is open. `Dispose` (or a lockdown) wipes them.
- Anyone who copies the file can try passwords offline. Ask for a long master password, and use
  [`Passwords.Check`](#checking-new-passwords) to make sure.

## Traps

Traps catch people trying to get around your security. When one goes off, Caltrop raises an **alarm**. What
happens next is up to you. Nothing is on until you turn it on.

### Alarms and lockdown

```csharp
// When your app starts:
Caltrop.Traps.Alarm += (_, alarm) =>
{
    logger.LogCritical("Caltrop alarm: {Kind} {Message} ({Subject})", alarm.Kind, alarm.Message, alarm.Subject);
    // block the IP, email the admin, end the session: your choice
};

Caltrop.Traps.LockDownOn = CaltropAlarmKind.DecoyUsed;   // optional
```

Some traps work by themselves, with no setup:

- The first time Caltrop is used, it checks that Caltrop.dll has not been changed.
- Changed encrypted data, forged tokens and signatures, and changed vaults and logs set off `Tampering` alarms.
- `Caltrop.Passwords.LogIn` locks out guessers and recognizes decoy accounts.
- Every alarm is recorded in Caltrop's own log (`caltrop.log`), before anything else happens. To record them
  somewhere else, set `Caltrop.Traps.Log` to a `CaltropLog` of your own.

There are four kinds of alarm:

| `CaltropAlarmKind` | Set off by |
| --- | --- |
| `DecoyUsed` | Using a [decoy](#decoys) |
| `TooManyAttempts` | A [lockout](#lockout) |
| `Tampering` | Changed encrypted data, files, vaults or logs; forged tokens and signatures; a changed Caltrop.dll |
| `Custom` | Your own traps: `Caltrop.Traps.Trigger("Fake admin page", ipAddress)` |

**Lockdown** is the spike. For the kinds in `LockDownOn`, Caltrop immediately wipes every key, key pair, open
vault and log key from memory, and every operation that uses a key, password or secret then throws a
`CaltropException` with `LockedDown`. It also removes `CALTROP_KEY` from the app's environment. Only
restarting the app undoes it: there is deliberately no unlock method. You can also lock down yourself with
`Caltrop.Traps.LockDown("reason")`.

Choose carefully what locks down:

- **Servers:** only `DecoyUsed`. Anyone can fail logins or send damaged data, so locking down on
  `TooManyAttempts` or `Tampering` would let an attacker switch your app off.
- **Local apps and tools** (a password manager, a wallet): `CaltropAlarmKind.All` can make sense, because an
  attack there means the device itself is in the wrong hands.

Alarm handlers run on the thread that tripped the trap: keep them quick. If a handler throws, Caltrop ignores
the exception, so a broken handler can never disable a trap. A handler can use Caltrop itself; if it sets off
another alarm, that alarm is recorded (and can still lock down) but does not call the handlers again, so a
handler can never call itself forever. `alarm.Message` and `alarm.Subject` can contain text from the attacker,
so encode them (`Caltrop.Safe.Html`) before showing them in a web page.

### Decoys

Decoys are fake secrets that look exactly like real ones. Plant them where an attacker would look. Real users
never touch them, so any use means someone is where they should not be. Decoys use your default key, so set
one first.

```csharp
// A fake admin account. Any login attempt against it sets off the alarm and fails.
db.Users.Add(new User { Name = "admin", PasswordHash = Caltrop.Decoys.PasswordHash() });

// A fake API key, planted in an old config file, a backup or a test repository.
string bait = Caltrop.Decoys.ApiKey("acme_live");

// Fake rows among your real encrypted data. Decrypting one returns the fake value and sets off the alarm,
// so the attacker does not notice.
db.Cards.Add(new Card { Number = Caltrop.Decoys.Encrypted("4111 1111 1111 1111") });

// Your own decoy values: fake emails, user names, record ids.
Caltrop.Decoys.Watch("ceo-backup@example.com", "fake CEO email");
if (Caltrop.Decoys.Check(loginEmail)) { /* the alarm has gone off */ }
```

Caltrop recognizes its decoys by itself in `Passwords.Verify`, `ApiKeys.IsWellFormed`, `ApiKeys.Verify`,
`ApiKeys.Hash` and `Decrypt`, so no other code changes. A decoy carries a hidden mark made with your key:
without the key it cannot be told apart from the real thing, and checking a decoy password takes as long as a
real one, so timing gives nothing away either.

### Lockout

`Caltrop.Passwords.LogIn` already uses one (`Caltrop.Passwords.Lockout`). For anything else, such as PIN codes,
recovery codes or requests per IP address, make a `CaltropLockout` and keep it for the life of your app:

```csharp
static readonly CaltropLockout Logins = new()
{
    MaxFailures = 5,                       // failures in a row before a lockout
    LockFor = TimeSpan.FromMinutes(15),    // how long it lasts
    SlowDown = true,                       // each failure waits longer: 0.25 s, 0.5 s, 1 s, 2 s, up to 4 s
};

if (Logins.IsLockedOut(email))
{
    return $"Too many attempts. Try again in {Logins.TimeLeft(email).Minutes + 1} minutes.";
}

bool ok = await Logins.TryAsync(email, () => Caltrop.Passwords.Verify(password, user.PasswordHash));
```

- While a name is locked out, the check is not even run, so guessing is impossible.
- Names ignore case. You can lock by user, by IP address, or both (use two lockouts).
- A success forgets earlier failures. `Logins.Reset(email)` unlocks someone by hand.
- Use `TryAsync` in web apps, so the slow-down does not block a thread.
- Counters live in memory. In a local app an attacker could restart it to reset them, so there the slow
  password hashing is the main protection.

### Tamper checks

Seal something now; check later that nothing changed. A seal is a short `cts_...` string made with your key,
so nobody without the key can make a matching seal for changed content.

```csharp
string seal = Caltrop.Tamper.Seal(settingsJson);            // text or bytes
bool unchanged = Caltrop.Tamper.Check(settingsJson, seal);

string fileSeal = Caltrop.Tamper.SealFile("prices.csv");
bool fileOk = Caltrop.Tamper.CheckFile("prices.csv", fileSeal);   // false if changed or deleted

string folderSeal = Caltrop.Tamper.SealFolder("plugins");   // names and contents, including hidden files
bool folderOk = Caltrop.Tamper.CheckFolder("plugins", folderSeal);
```

Keep seals away from what they protect (in your database, or in your code), or an attacker could replace both.

`Caltrop.Tamper.CheckCaltrop()` checks Caltrop.dll itself. Every build stamps the DLL with a hash of its own
contents; if anyone changes even one byte afterwards, it returns `CaltropIntegrity.Changed` and the alarm goes
off. Caltrop runs this check by itself the first time it is used; call it to check again. It catches damaged
files and casual tampering. A skilled attacker who can
change files on the machine could also change the check, so treat it as one layer of defence.

## Tamper-proof log

The quickest way is Caltrop's own log, `caltrop.log` in [Caltrop's folder](#caltrops-folder). Alarms are recorded
there too:

```csharp
Caltrop.Log("alice changed her password");
CaltropLogCheck check = Caltrop.CheckLog();   // check.IsIntact, check.Problem
```

For a log in a file you choose, use `CaltropLog`. It writes a plain text log where each entry is chained to the
one before it with your key:

```csharp
using var log = new CaltropLog("security.log");   // or new CaltropLog(path, key)
log.Write("alice logged in");
log.Write("alice changed her password");

CaltropLogCheck check = log.Verify();
if (!check.IsIntact)
{
    Console.WriteLine(check.Problem);   // "Entry 2 (line 3) was changed."
}

foreach (CaltropLogEntry entry in log.Read())   // throws if the log was tampered with
{
    Console.WriteLine($"{entry.Number} {entry.Time:u} {entry.Message}");
}
```

Editing, deleting, inserting, reordering or copying in entries is detected. What a log alone cannot notice is
its newest entries (or the whole file) being deleted, because what is left still checks out. To catch that,
save `log.Head` somewhere else now and then, and check against it:

```csharp
string head = log.Head;                                       // e.g. "42:Xq3..." store it elsewhere
CaltropLogCheck later = CaltropLog.Verify("security.log", expectedHead: head);
```

- The file stays readable in any text editor, one entry per line. Windows line endings are fine.
- Several programs can write to the same log at once: entries are added one at a time, so none is lost or
  mixed up.
- If the app crashes halfway through writing an entry, the next entry still starts on a line of its own, and
  `Verify` reports the cut-off line.
- Opening a log checks it, if it is under 8 MB (so opening stays quick). `Verify` always checks the whole file.
- One entry can be up to 1,000,000 characters.

## Safe input

Helpers for anything that comes from outside your app:

```csharp
// Keep paths inside a folder. Throws CaltropException (UnsafeInput) for "../../secret.txt", "C:\x",
// "\\server\share", device names like "CON", and links that point outside the folder.
string path = Caltrop.Safe.PathInside("uploads", request.FileName);

// A safe file name to save an upload as: no folders, no forbidden or invisible characters, no reserved names.
string name = Caltrop.Safe.FileName(upload.FileName);   // "../../evil.exe" becomes "evil.exe"

// Show user text in a web page without it ever becoming markup.
string html = $"<p>{Caltrop.Safe.Html(comment)}</p>";

// Hide secrets before logging: card numbers, emails, Caltrop and API keys, bearer and JWT tokens,
// and values like password=..., token: ..., "api_key": "...".
logger.LogInformation(Caltrop.Safe.Mask(requestBody));

// Remove invisible and right-to-left characters that can disguise text, like "photo_\u202Egpj.exe".
string userName = Caltrop.Safe.CleanText(input);

// Only allow http, https, mailto and relative links (blocks javascript:, data:, and disguised versions).
if (Caltrop.Safe.IsSafeLink(profileUrl)) { /* safe to use in href */ }
```

`Mask` recognizes common patterns, so it reduces leaks but cannot promise to catch every secret.

## Tokens

Tokens carry a small payload that users cannot read or change, and they expire:

```csharp
string token = Caltrop.Tokens.Create(user.Id.ToString(), key, TimeSpan.FromHours(1), purpose: "password-reset");

// Later, when the link is opened
if (Caltrop.Tokens.TryValidate(token, key, out string? userId, purpose: "password-reset"))
{
    // genuine, not expired, made for password resets
}
```

- **Purpose** keeps features apart: a token made for `"email-verify"` is rejected by `"password-reset"`.
- `Validate` throws a `CaltropException` with `ErrorCode` `TokenExpired` or `AuthenticationFailed`;
  `TryValidate` returns `false` instead.
- `TimeSpan.MaxValue` makes a token that never expires.
- A token has exactly one text form (whitespace around it aside), so tokens can be compared as text.
- Tokens are stateless, so a token works until it expires, even after it has been used. For one-time links,
  put something in the payload that changes when the link is used, such as a security stamp that changes with
  the password, and check it:

```csharp
string token = Caltrop.Tokens.Create($"{user.Id}:{user.SecurityStamp}", key, TimeSpan.FromHours(1), "password-reset");
```

## Files and streams

```csharp
Caltrop.Files.EncryptFile("report.pdf", "report.pdf.caltrop", key);
Caltrop.Files.DecryptFile("report.pdf.caltrop", "report.pdf", key);

await Caltrop.Files.EncryptFileAsync(inputPath, outputPath, key, cancellationToken);
Caltrop.Files.EncryptFileWithPassword("backup.zip", "backup.zip.caltrop", password);
```

- Any size works: data is processed in 64 KiB chunks, never loaded whole.
- The file methods write to a temporary file and replace the output only after everything has been checked,
  so a damaged or tampered file never leaves a partial output. On Linux and macOS, decrypted files are only
  readable by the current user. Input and output may be the same path.
- Reordered, removed, added or cut-off data is always detected.

The stream methods work with uploads, blobs and network streams:

```csharp
public async Task SaveUploadAsync(Stream upload, string path, CancellationToken cancellationToken)
{
    await using FileStream output = File.Create(path);
    await Caltrop.Files.EncryptAsync(upload, output, key, cancellationToken);
}
```

Stream decryption writes as it goes. If it throws, discard what was written. If nothing unverified may be
used, for example before sending a file to a client, decrypt to a file with `DecryptFileAsync` first.

## Public keys and signatures

A `CaltropKeyPair` has a private half that you keep and a public half (`ctpub_...`) that you can share.

```csharp
using var alice = CaltropKeyPair.Generate();
string publicText  = alice.PublicKey.Export();    // share freely
string privateText = alice.ExportPrivateKey();    // keep secret; reload with CaltropKeyPair.Parse
```

### Encrypting for someone

```csharp
var recipient = CaltropPublicKey.Parse(publicText);
string encrypted = Caltrop.Encrypt("for Alice only", recipient);

string plain = Caltrop.Decrypt(encrypted, alice);   // only Alice's key pair can do this
```

You do not need to share a secret first. Every message uses a new temporary key, so one leaked message key
reveals nothing about others.

### Signing

```csharp
string signature = Caltrop.Sign("release v1.2.0", alice);
bool genuine = Caltrop.VerifySignature("release v1.2.0", signature, alice.PublicKey);
```

Signatures work on text, bytes and streams. A common use is licence keys: sign the licence on your server and
embed only the public key in your app, which can then check licences offline.

```csharp
string licence   = $"{email}|pro|2027-12-31";
string signature = Caltrop.Sign(licence, vendorKeys);

// In the app
bool valid = Caltrop.VerifySignature(licence, signature, CaltropPublicKey.Parse(EmbeddedPublicKey));
```

`VerifySignature` never throws for a bad signature; it returns `false`.

## API keys

```csharp
// Issuing: show the key once, store only the hash
string apiKey = Caltrop.ApiKeys.Generate("acme_live");   // acme_live_4fT9... (prefix, 32 random, 6 checksum)
customer.ApiKeyHash = Caltrop.ApiKeys.Hash(apiKey);
```

Checking a request, for example in ASP.NET Core middleware:

```csharp
app.Use(async (context, next) =>
{
    string? apiKey = context.Request.Headers["X-Api-Key"];
    if (!Caltrop.ApiKeys.IsWellFormed(apiKey, "acme_live"))   // cheap: no database call for junk
    {
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        return;
    }

    string hash = Caltrop.ApiKeys.Hash(apiKey);
    var customer = await db.Customers.SingleOrDefaultAsync(c => c.ApiKeyHash == hash);
    // ...
    await next(context);
});
```

The checksum lets `IsWellFormed` reject typos and random input without a lookup, and lets secret scanners
find leaked keys by their prefix. Because keys are long and random, a fast hash is safe to store and index. To
revoke a key, delete its hash.

## Webhooks

### Receiving

Verify the **raw body bytes**, before parsing them:

```csharp
app.MapPost("/webhooks/github", async (HttpRequest request) =>
{
    using var buffer = new MemoryStream();
    await request.Body.CopyToAsync(buffer);
    byte[] body = buffer.ToArray();

    if (!Caltrop.Webhooks.Verify(body, request.Headers["X-Hub-Signature-256"], webhookSecret))
    {
        return Results.Unauthorized();
    }

    var payload = JsonSerializer.Deserialize<PushEvent>(body);
    // ...
    return Results.Ok();
});
```

`Verify` accepts hex or Base64 signatures, with or without a `sha256=` prefix, which covers GitHub, Shopify
and most providers that sign the body with HMAC-SHA256.

### Sending

```csharp
string secret = Caltrop.Webhooks.CreateSecret();   // whsec_..., share it with the receiver once
string header = Caltrop.Webhooks.SignWithTimestamp(body, secret);   // t=1731234567,v1=5257a8...
```

The receiver calls `Caltrop.Webhooks.VerifyWithTimestamp(body, header, secret)`, which also rejects signatures
more than 5 minutes old, so captured requests cannot be replayed later. A header may contain several `v1=`
values, which lets you rotate secrets without downtime.

## Hashing and searching encrypted data

```csharp
Caltrop.Hashing.Sha256("abc");            // ba7816bf...
Caltrop.Hashing.Sha256File("setup.exe");  // same as sha256sum
Caltrop.Hashing.HmacSha256(message, secret);
```

### Blind indexes

Encrypted columns cannot be searched, because each encryption is different. Store a blind index next to the
value, a keyed hash that is the same every time for the same input:

```csharp
string normalized = email.Trim().ToLowerInvariant();
customer.EmailEncrypted = Caltrop.Encrypt(normalized, key);
customer.EmailIndex     = Caltrop.Hashing.BlindIndex(normalized, key, "customers.email");

// Find a customer by email without decrypting anything
string index = Caltrop.Hashing.BlindIndex(input.Trim().ToLowerInvariant(), key, "customers.email");
var match = await db.Customers.SingleOrDefaultAsync(c => c.EmailIndex == index);
```

Without the key, nobody can compute or reverse the index. It does show which rows have equal values, so only
index columns where that is acceptable.

## Random values

```csharp
Caltrop.Random.Token();          // 43-character URL-safe token: session ids, CSRF tokens
Caltrop.Random.Password();       // 20 characters with upper, lower, digits and symbols
Caltrop.Random.String(10);       // letters and digits
Caltrop.Random.String(6, "0123456789");   // e.g. a numeric code
Caltrop.Random.Number(1, 7);     // 1 to 6, unbiased
Caltrop.Random.Bytes(32);
```

All values come from the operating system's secure random number generator. Never use `System.Random` for
secrets.

## Errors and troubleshooting

Start with `Console.WriteLine(Caltrop.Status())`. It shows where the key comes from, which folder Caltrop uses,
whether the log and secrets are intact and how the traps are set, and says what to do about any problem. It never
makes a key or a file.

| What you see | Usual cause | Fix |
| --- | --- | --- |
| `KeyMismatch`: "encrypted with a different key (key id ...)" | The wrong key is loaded, for example a development key in production. | Compare `key.Id` with the id in the message. During rotation, use a key ring that includes the old key. |
| `AuthenticationFailed` | The data was changed, or the context, purpose or password differs. | Check that the context or purpose is exactly the same as when encrypting. |
| `InvalidFormat`: "too short" | The value was cut off, often by a database column that is too small. | Make the column bigger (see the size table above). |
| `WrongDataType` | A method was given another kind of Caltrop data. | Use the method the message names. |
| `TokenExpired` | The token is older than its lifetime. | Ask the user to request a new link. |
| `LockedDown` | A trap made Caltrop lock itself down. | Find out why (`Caltrop.Traps.LockedDownBy`, your alarm log), then restart the app. |
| `UnsafeInput` | `Safe.PathInside` rejected a path. | Expected for attacks. For real users, show a "bad file name" error. |
| `InvalidOperationException`: "Caltrop has no key" | Caltrop has nowhere to keep its own key, for example in a container. | Set `CALTROP_KEY`, or `CALTROP_FOLDER` to a kept folder. See [Caltrop's key](#caltrops-key). |
| `InvalidOperationException`: "could not create its folder" or "could not save its key" | The app may not write to [Caltrop's folder](#caltrops-folder), for example a service account. | Set `CALTROP_FOLDER` to a folder the app can write to, or give it a key with `CALTROP_KEY`. |
| `IOException`: "another program has kept it busy" | Another program held a vault or log for over 10 seconds. | Close the other program, or try again. |
| `KeyMismatch` after moving to another computer | The data was encrypted with the other computer's `caltrop.key`. | Copy that `caltrop.key` into [Caltrop's folder](#caltrops-folder), or use the same `CALTROP_KEY` on both. |
| `PlatformNotSupportedException` | The platform has no AES-GCM, for example Blazor WebAssembly. | Run Caltrop on the server. |

## Performance and thread safety

- Every `Caltrop` method is thread-safe, and key objects are immutable, so share them freely.
- Encryption runs at hardware AES speed, typically more than 1 GB/s. Each message derives its own key, which
  adds about a microsecond.
- Password hashing and password encryption are slow on purpose (roughly 0.1 to 0.5 seconds). Rate-limit login
  endpoints.
- `Dispose` on keys wipes them from memory. It is optional, and only safe once nothing else uses the key.
- A vault or log can be shared by several threads, and by several programs at once (see [Caltrop's folder](#caltrops-folder)).
