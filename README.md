<p align="center"><img src="assets/logo.png" alt="Caltrop logo" width="180"></p>

<h1 align="center">Caltrop</h1>

**Drop-in security for .NET.** Add one file, then write one line. Caltrop looks after keys, passwords, secrets
and traps for you.

```csharp
string secret = Caltrop.Encrypt("4111 1111 1111 1111");
string card   = Caltrop.Decrypt(secret);
```

There is nothing to set up. The first time Caltrop needs a key, it makes one and keeps it safe.

## Add it to your project

1. Download [**Caltrop.dll**](../../releases/latest/download/Caltrop.dll).
2. In Visual Studio, right-click **Dependencies** → **Add Project Reference** → **Browse**, and pick the file.
   Or add this to your `.csproj`: `<ItemGroup><Reference Include="Caltrop" HintPath="Caltrop.dll" /></ItemGroup>`
3. That's it. Type `Caltrop.` and pick what you need. No `using` line, no keys, no settings.

Caltrop needs .NET 10 or later, and works fully offline: it never connects to the internet.

## Everyday use

### Encrypt anything

```csharp
string secret = Caltrop.Encrypt("Alice's card number");
string plain  = Caltrop.Decrypt(secret);
```

If anyone changes the encrypted text, `Decrypt` throws instead of returning garbage.

### Passwords: sign-up and login

```csharp
// Sign-up (or password change)
var result = Caltrop.Passwords.Create(password, user.Name, user.Email);
if (!result.Ok) return result.Message;            // "This is one of the most common passwords..."
user.PasswordHash = result.Hash;

// Login
var login = Caltrop.Passwords.LogIn(email, password, user?.PasswordHash);
if (!login.Ok) return login.Message;              // "Wrong user name or password."
if (login.NewHash is not null) user.PasswordHash = login.NewHash;
```

Those two calls do everything for you:

- reject weak passwords, the 10,000 most common ones, and the user's own name
- lock out anyone who guesses wrong 5 times, for 15 minutes
- make every wrong guess slower
- answer just as fast whether or not the account exists
- raise the alarm on decoy accounts
- upgrade old hashes

In web apps, use `LogInAsync`.

### Keep secrets

```csharp
Caltrop.Secrets.Set("db-password", "hunter2");
string? db = Caltrop.Secrets.Get("db-password");
```

Secrets are saved encrypted, straight away.

### Keep a log nobody can secretly edit

```csharp
Caltrop.Log("alice changed her password");
bool untouched = Caltrop.CheckLog().IsIntact;
```

### Check that everything is set up

```csharp
Console.WriteLine(Caltrop.Status());
```

```text
Caltrop 1.0.0: everything is fine.
  Caltrop.dll  not changed since it was built
  Key          C:\Users\me\AppData\Local\Caltrop\MyApp\caltrop.key (back this file up)
  Folder       C:\Users\me\AppData\Local\Caltrop\MyApp
  Log          12 entries, none changed
  Secrets      2 secrets
  Traps        alarms go to Caltrop's log; 1 alarm handler; lockdown on DecoyUsed
```

It never makes a key or a file. If something is wrong, `Caltrop.Status().Ok` is `false` and each problem says what to do.

### Handle input from users safely

```csharp
string path = Caltrop.Safe.PathInside("uploads", fileName);   // blocks "../../secret.txt"
string name = Caltrop.Safe.FileName(upload.FileName);          // a plain, safe file name
string html = Caltrop.Safe.Html(comment);                      // can't become a <script>
string line = Caltrop.Safe.Mask(requestBody);                  // hides cards, emails, passwords for logs
bool isSafe = Caltrop.Safe.IsSafeLink(url);                    // blocks javascript: links
```

## Traps

Some protection is always on:

- Caltrop checks that Caltrop.dll hasn't been changed.
- It notices changed data, forged tokens and forged signatures.
- It records every alarm in its log.

You can add more with one line each:

```csharp
Caltrop.Traps.Alarm += (_, alarm) => Console.WriteLine(alarm);   // be told when a trap goes off
Caltrop.Traps.LockDownOn = CaltropAlarmKind.DecoyUsed;           // the spike: wipe all keys and stop

// Decoys look real. Anyone who uses one sets off the alarm.
db.Users.Add(new User { Name = "admin", PasswordHash = Caltrop.Decoys.PasswordHash() });
db.Cards.Add(new Card { Number = Caltrop.Decoys.Encrypted("4111 1111 1111 1111") });
string bait = Caltrop.Decoys.ApiKey("acme_live");                // plant it where thieves look

// Seal files, then check them later.
string seal = Caltrop.Tamper.SealFile("settings.json");
bool same = Caltrop.Tamper.CheckFile("settings.json", seal);
```

A **lockdown** wipes every key from memory and stops Caltrop until the app restarts. On a server, only lock down
on `DecoyUsed`. Anyone can fail a login or send damaged data, so locking down on those would let an attacker
switch your app off on purpose.

## Where Caltrop keeps its things

Caltrop keeps a small folder for your app:

| System | Folder |
| --- | --- |
| Windows | `%LOCALAPPDATA%\Caltrop\<YourApp>` |
| macOS | `~/Library/Application Support/Caltrop/<YourApp>` |
| Linux | `~/.local/share/Caltrop/<YourApp>` |

| File | What it is |
| --- | --- |
| `caltrop.key` | The key that protects your data. **Back it up.** If you lose it, data encrypted with it is gone. |
| `secrets.vault` | Your `Caltrop.Secrets`, encrypted. |
| `caltrop.log` | The tamper-proof log, including every alarm. |

Several copies of your app can share these files at once, and no secret or log entry is lost.

On **servers and in containers**, give every copy of your app the same key: set the `CALTROP_KEY` environment
variable to a key (print one with `Console.WriteLine(CaltropKey.Generate().Export())`).

- **Containers:** Caltrop never makes a key of its own there, because it would be lost when the container is
  replaced. For `Caltrop.Secrets` and `Caltrop.Log` in a container, also set `CALTROP_FOLDER` to a volume that is kept.
- **Another folder:** set `CALTROP_FOLDER` or `Caltrop.Folder` to keep Caltrop's files somewhere else.

## More

| You want to | Use |
| --- | --- |
| Encrypt with a password (wallet seed phrases, private keys) | `Caltrop.EncryptWithPassword` |
| Encrypt big files | `Caltrop.Files.EncryptFile` |
| Encrypt for one person, or sign data | `CaltropKeyPair`, `Caltrop.Sign` |
| Make expiring links (password reset, invites) | `Caltrop.Tokens` |
| Issue API keys, check webhooks | `Caltrop.ApiKeys`, `Caltrop.Webhooks` |
| A vault in your own file, with its own password | `CaltropVault` |
| Your own lockout rules | `Caltrop.Passwords.Lockout`, `CaltropLockout` |
| Your own password rules | `Caltrop.Passwords.Rules` |
| Use your own key | `Caltrop.UseKey`, or `CALTROP_KEY` |
| Hashes, random values, safe comparisons | `Caltrop.Hashing`, `Caltrop.Random`, `Caltrop.SecureEquals` |

The [guide](docs/guide.md) explains everything with examples.

## When something goes wrong

Caltrop throws a `CaltropException`. Its message says what to do, and its `ErrorCode` says why:

| `ErrorCode` | Meaning |
| --- | --- |
| `AuthenticationFailed` | The data was changed, or the key, password or context is wrong. |
| `KeyMismatch` | The data was made with another key, for example on another computer. |
| `LockedDown` | A trap made Caltrop lock itself down. Restart the app. |
| `UnsafeInput` | Input was rejected, for example a path that leaves its folder. |
| `TokenExpired`, `WrongDataType`, `InvalidFormat`, `InvalidKey`, `UnsupportedVersion` | See the [guide](docs/guide.md#errors-and-troubleshooting). |

## Build it yourself

Install the [.NET 10 SDK](https://dotnet.microsoft.com/download), then double-click `build.cmd` (Windows) or
run `bash build.sh` (macOS, Linux). It runs every test, then puts `Caltrop.dll` in the `release` folder and
prints its SHA-256 and the SDK version. If a test fails, no DLL is made. The first build needs the internet once,
to download the test tools; after that it works offline.

Builds are reproducible: building the same source with the same SDK version gives exactly the same
`Caltrop.dll`, whatever folder it is built in. Nothing about the computer that built it (such as its folders or
your user name) ends up inside the DLL.

## Publish a release

1. Run the build script. Your DLL is in the `release` folder.
2. On GitHub, open **Releases** → **Draft a new release**.
3. Under **Choose a tag**, type a version such as `v1.0.0`, and pick **Create new tag on publish**.
4. Drag `release/Caltrop.dll` (and `release/Caltrop.xml`, for method descriptions in editors) into the box.
5. Paste the two lines the build printed (the SHA-256 and the SDK version) into the notes, then click
   **Publish release**.

The download link at the top always gets the newest release. Don't upload the `artifacts` or `release`
folders to the repository itself.

To check a download, compare its SHA-256 with the release notes: `Get-FileHash Caltrop.dll` (Windows, which shows
it in capital letters) or `shasum -a 256 Caltrop.dll` (macOS, Linux).

To check that a release really was built from this source, build that version yourself with the SDK version
from its notes and compare the SHA-256. If you have several SDKs, pick that one first by running
`dotnet new globaljson --sdk-version <version>` in the Caltrop folder.

## Security

Caltrop only combines the cryptography built into .NET (AES-256-GCM, PBKDF2, HKDF, HMAC, ECDSA) and never
implements its own. It has not had an independent security audit yet: please have it reviewed before you rely
on it for high-stakes data, such as wallets holding real money. How it works and its limits are in
[docs/security-model.md](docs/security-model.md) and [docs/format.md](docs/format.md). To report a problem,
see [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE). The common-password list comes from [SecLists](https://github.com/danielmiessler/SecLists)
(MIT); see [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
