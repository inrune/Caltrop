# Security model

What Caltrop protects against, what it does not, and why it is built the way it is.

## Goals

- **Confidentiality.** Without the key (or password, or private key), encrypted data reveals nothing except
  its length.
- **Integrity.** Any change to encrypted data, tokens, signatures or files is detected. Caltrop throws (or
  returns `false`) rather than returning modified data.
- **Hard to misuse.** No modes, IVs or padding to choose. Nonces are random and large. Comparisons of secrets
  are constant-time. Different features use separate derived keys, so a value made by one feature is never
  accepted by another.
- **Long-term compatibility.** Every output is versioned. Future versions can change algorithms and still
  read old data.
- **Catch attackers, not just stop them.** Traps (decoys, lockouts, tamper checks) raise alarms, and can make
  Caltrop wipe its keys and lock itself down. Every trap is off until the app turns it on.

## Design choices

**Only platform primitives.** AES-GCM, ECDH, ECDSA, SHA-2, HMAC, HKDF and PBKDF2 all come from
`System.Security.Cryptography`, which uses the operating system's audited implementations (CNG on Windows,
OpenSSL on Linux, Apple's libraries on macOS). Caltrop only combines them.

**Offline by design.** Caltrop makes no network calls and starts no other programs. It reads only the data and
files you give it, its own folder, its own DLL (for the self-check), and three environment variables:
`CALTROP_KEY`, `CALTROP_FOLDER` and `DOTNET_RUNNING_IN_CONTAINER`. It writes only the files you ask for and its
own folder. `OfflineTests` fails the build if the library ever references .NET's networking or process
assemblies.

**One spelling per value.** Each key, token, ciphertext, signature, seal, password hash and log line is read in
exactly one text form (whitespace around it aside). .NET's own decoders would also accept spaces or padding
inside Base64, a different last character for the same bytes, or a number with leading zeros or a trailing NUL;
Caltrop rejects them. So a changed text is never mistaken for the original, which matters if an app compares or
stores values as text.

**Broken input is just wrong.** A password or API key containing half of a surrogate pair (which browsers cannot
send, but other clients can) is simply wrong, after the same amount of work, rather than an exception. Fuzz tests
feed thousands of damaged and random values into every reader on every build: the only answers allowed are "no"
and a `CaltropException`.

**Reproducible builds.** Building the same source with the same .NET SDK version gives byte-for-byte the same
`Caltrop.dll`, wherever it is built: the build machine's folders are replaced by `/_/`, nothing about git is
included, and `.gitattributes` keeps line endings the same on every computer. So anyone can rebuild a release
and compare its SHA-256. The DLL contains its source code, so a debugger can step into it offline.

**Files are never left half-written.** Vaults, encrypted files and Caltrop's key are written to a temporary file in
the same folder, flushed to disk, and then moved into place, so a crash or power cut leaves the old file or the
new one. Logs only ever have whole lines added.

**Sharing files safely.** Several programs (or copies of one app) can use the same vault, log or Caltrop folder at
once. A program that changes a vault or log first opens an empty `<file>.lock` exclusively, so changes take
turns and none is lost; the operating system releases it if the program crashes. Readers never wait: a vault
notices that someone else saved (each save has a new random nonce) and reloads, and a log reader ignores a line
that is still being written. Two copies of an app making Caltrop's key at the same moment take turns too, so
they always end up with one key. A file that stays busy (another program, a virus scanner) is retried for 10
seconds before a clear error.

**A key without setup.** If the app sets no key, Caltrop makes one and keeps it in `caltrop.key` in its own
folder in the user's local app data. On Linux and macOS the folder is created readable only by the user (0700)
and the file 0600; on Windows the user's app data folder is already private to the user. Copies of an app that
start at once take turns making the key file (see above), so they agree on one key, and a damaged key file is
reported, never replaced. In a container (`DOTNET_RUNNING_IN_CONTAINER`), Caltrop refuses to
make a key of its own, because it would be lost with the container, and the data with it.

**A key per message.** AES-GCM fails badly if a nonce repeats under the same key. Caltrop draws a 192-bit
random nonce for every message and derives a fresh AES key from it with HKDF, so repeats are not a practical
concern however many messages one key encrypts (a similar idea to XAES-256-GCM).

**Key ids.** Each blob names the key it was made with (4 bytes, derived one-way from the key). This makes key
rotation automatic and turns "wrong key" into a clear error instead of a generic failure. It reveals which
key was used, not anything about the key.

**PBKDF2 for passwords.** Argon2 or scrypt resist GPU cracking better, but .NET has no built-in
implementation and Caltrop takes no dependencies. PBKDF2-HMAC-SHA256 with 600,000 iterations is the current
OWASP recommendation, and the iteration count is stored with every hash, so it can be raised later
(`Passwords.NeedsRehash`).

**Two P-256 keys per key pair.** Using one key for both ECDH and ECDSA is discouraged, so a `CaltropKeyPair`
holds one of each. P-256 is used because it is supported natively on every platform .NET runs on.

**Lockdown wipes, then refuses.** On lockdown Caltrop first sets a flag, then zeroes every live key, key
pair, open vault and log key it knows about (it tracks them with weak references). Every operation that uses
key material checks the flag before it starts and again before it returns a result, so nothing made with a
half-wiped key can escape. It also removes `CALTROP_KEY` from the process's environment. There is no unlock
method: restarting the app is the only way back. (Code running inside the same process can still tamper with
Caltrop through reflection, as it can with any .NET library; see "Not protected" below.)

**Decoys hide in randomness.** A decoy's mark lives in bytes that are random in real values (a salt, a nonce,
the random part of an API key) and is an HMAC under the app's key, so without the key a decoy looks exactly
like real data. A decoy password check still runs the full PBKDF2, so timing does not reveal it.

**Alarms never break the trap.** Alarm handlers run synchronously, and exceptions they throw are ignored, so a
buggy handler cannot disable a trap. Alarms are recorded in the log before a lockdown wipes the log key. An alarm
set off inside a handler is recorded but does not call the handlers again, so a handler that trips a trap (for
example by reading a damaged vault) cannot loop forever.

**Chunked streams.** Files use the STREAM construction: each 64 KiB chunk is authenticated on its own, and
its position and a "last chunk" flag are part of its nonce. This allows files of any size while still
detecting reordering, truncation and appended data.

## Not protected

- **Anyone who can read the user's files.** Caltrop's own key file is protected by the operating system's file
  permissions, like an SSH key. Malware running as the same user, an administrator, or someone with the
  unencrypted disk can read it. For servers, keep the key in a secret manager and pass it in `CALTROP_KEY`.
- **A lost key file.** If `caltrop.key` is deleted and there is no backup, data encrypted with it cannot be
  recovered. Back it up.
- **A compromised server.** Anyone who can read your process memory, configuration or secret store can read
  the keys, and therefore the data.
- **Leaked keys.** There is no way to "un-leak" a key. Rotate it and re-encrypt.
- **Length.** Ciphertext is a fixed amount longer than the plaintext. Pad values yourself if their length is
  sensitive.
- **Equality in blind indexes.** Equal values have equal indexes by design.
- **Weak passwords.** Password-based encryption and stored password hashes can be attacked offline by
  guessing. PBKDF2 slows this down; it cannot make a weak password strong.
- **Replay of tokens.** Tokens are stateless and work until they expire. See the guide for single-use tokens.
- **Streaming decryption output.** Stream decryption writes data before the end of the stream has been
  verified. If it throws, discard the output. The file methods handle this for you.
- **Memory hygiene.** Caltrop wipes keys and temporary buffers when it can, but .NET strings cannot be wiped,
  and the garbage collector may copy data. Treat this as defence in depth, not a guarantee.
- **An attacker who controls the machine.** Traps, lockdowns and `Tamper.CheckCaltrop` raise the cost of an
  attack, but someone who can change files or memory on the machine can also change Caltrop itself. They are
  layers of defence, not guarantees.
- **Denial of service through traps.** Anything that locks down on input an outsider can send (failed logins,
  damaged data) lets that outsider switch the app off. On servers, only lock down on `DecoyUsed`.
- **Lockout state across restarts.** `CaltropLockout` counts in memory, so restarting the app resets it.
- **Deleted newest log entries.** A log alone cannot notice its newest entries (or the whole file) being
  deleted. Keep `CaltropLog.Head` somewhere else to catch it.
- **Changes to an open vault's file that keep its header.** An open vault reloads when the file's nonce changes.
  If someone changes the rest of the file and keeps the nonce, the open vault keeps using its own (correct) copy,
  and the change is noticed the next time the vault is opened, unless a save from the open vault replaces it first.
- **Big logs when they are opened.** Logs over 8 MB are not checked when they are opened, only by `Verify`, so
  that opening stays quick.
- **Side channels in the platform.** Timing and cache behaviour of the underlying primitives are up to the OS
  libraries. Modern CPUs with AES instructions make AES-GCM constant-time.

## Limits

| Item | Limit |
| --- | --- |
| Messages per key | No practical limit (per-message keys). |
| In-memory message size | About 2 GB (.NET array limit). Use `Caltrop.Files` beyond that. |
| Stream size | No practical limit (2^64 chunks of 64 KiB). |
| Vault size | 64 MiB of secrets per vault file. |
| Lockout memory | `MaxTracked` names (default 100,000); names that are not locked out are forgotten first. |

## Status

Caltrop has not yet been independently audited. Please review it, or have it reviewed, before you rely on it
for high-stakes data. Vulnerability reports are welcome; see [SECURITY.md](../SECURITY.md).

Each release lists the SHA-256 of its `Caltrop.dll`, so you can check a download (see
[Publish a release](../README.md#publish-a-release)), and `Caltrop.Tamper.CheckCaltrop()` checks the file at runtime.
