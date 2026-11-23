# Changelog

All notable changes to Caltrop are listed here. Versions follow [Semantic Versioning](https://semver.org/).

## 1.0.0

First release: one DLL, no dependencies, fully offline, and nothing to set up.

### Nothing to set up

- Add `Caltrop.dll` and start: the public types have no namespace, so no `using` line is needed.
- Caltrop makes and keeps its own key (`caltrop.key` in `Caltrop.Folder`) the first time it needs one.
  `CALTROP_KEY` and `Caltrop.UseKey` still come first. In containers it asks for `CALTROP_KEY` instead of
  making a key that would be lost.
- `Caltrop.Passwords.Create` and `Caltrop.Passwords.LogIn` handle user passwords in two calls: strength check,
  hashing, lockout, slow-down, equal timing for unknown users, decoy accounts and hash upgrades.
- `Caltrop.Secrets` keeps secrets and `Caltrop.Log` keeps a tamper-proof log, with nothing to set up.
- Caltrop checks Caltrop.dll on first use, and records every alarm in its log.
- `Caltrop.Status()` shows in one call whether Caltrop is set up right: the key and which file to back up, the
  folder, the log, the secrets, the self-check and the traps. It never makes a key or a file.

### Reliable

- Several programs, or several copies of one app, can share a vault, a log and Caltrop's folder at once: they
  take turns on the files, see each other's changes, lose nothing, and agree on one key even when they start
  together.
- Vaults, encrypted files and Caltrop's key are written to a temporary file, flushed to disk and moved into
  place, so a crash or power cut never leaves half a file.
- A busy file (another program, a virus scanner) is retried for up to 10 seconds, then gives a clear error.
- Clear errors when Caltrop's folder cannot be created or its key cannot be saved.
- An alarm handler can use Caltrop safely: an alarm it sets off itself is recorded but never calls it again.
- Every value has exactly one text form: spaces or padding inside, other spellings of the same Base64 and numbers
  with leading zeros are rejected, so a changed text is never taken for the original.
- A password or API key with broken Unicode is simply wrong, never an exception. Fuzz tests feed thousands of
  damaged values into every reader on every build.

### Protect data

- `Caltrop.Encrypt` / `Decrypt` for text and bytes: AES-256-GCM with a fresh key per message, optional context
  binding, and key rotation with `CaltropKeyRing`.
- A default key from the `CALTROP_KEY` environment variable or `Caltrop.UseKey`.
- Password encryption (`EncryptWithPassword`), suitable for wallet seed phrases and private keys.
- `CaltropVault`: named secrets in one encrypted file, locked with a password or a key.
- `Caltrop.Files`: encryption of files and streams of any size, in 64 KiB chunks.
- Public-key encryption and ECDSA signatures with `CaltropKeyPair` and `CaltropPublicKey`.

### Passwords and access

- `Caltrop.Passwords`: hashing (PBKDF2, PHC format) and `Check`, an offline strength check that rejects the
  10,000 most common passwords, their look-alikes, repeats, sequences and the user's own name or email.
- `Caltrop.Tokens`: encrypted, expiring tokens with purposes.
- `Caltrop.ApiKeys`, `Caltrop.Webhooks`, `Caltrop.Hashing`, `Caltrop.Random`, `Caltrop.SecureEquals`.

### Traps

- `Caltrop.Traps`: alarms for every trap, and an optional lockdown that wipes every key from memory and stops
  Caltrop until the app restarts. You choose which alarms lock down.
- `Caltrop.Decoys`: decoy password hashes, API keys and encrypted values, recognized automatically, plus
  watched values of your own.
- `CaltropLockout`: locks out a user after too many failures, and slows down every failed attempt.
- `Caltrop.Tamper`: seals for data, files and folders, and `CheckCaltrop()` to spot a changed Caltrop.dll.
- Tampering alarms for changed encrypted data, forged tokens and signatures, and changed vaults and logs.
- `CaltropLog`: a tamper-proof log that records alarms too.

### Safe input

- `Caltrop.Safe`: keep paths inside a folder, safe file names, HTML encoding, masking secrets in logs,
  removing invisible characters, and safe links.

### Build

- Double-click `build.cmd` (or run `bash build.sh`) to run every test and build `Caltrop.dll`. It checks for
  the .NET 10 SDK first, and works offline once the test tools have been downloaded.
- Every build seals `Caltrop.dll` for its self-check.
- Reproducible builds: the same source and SDK version give exactly the same `Caltrop.dll`, and no folder or
  user name from the build machine ends up inside it. The DLL carries its source code for debuggers.
- No network code and no starting other programs: the tests enforce it.
