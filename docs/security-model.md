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

## Design choices

**Only platform primitives.** AES-GCM, ECDH, ECDSA, SHA-2, HMAC, HKDF and PBKDF2 all come from
`System.Security.Cryptography`, which uses the operating system's audited implementations (CNG on Windows,
OpenSSL on Linux, Apple's libraries on macOS). Caltrop only combines them.

**Offline by design.** Caltrop makes no network calls and starts no other programs. It reads only the data and
files you give it and the `CALTROP_KEY` environment variable. It writes only the files you ask for, through a
temporary file in the same folder that is moved into place when complete. `OfflineTests` fails the build if
the library ever references .NET's networking or process assemblies.

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

**Chunked streams.** Files use the STREAM construction: each 64 KiB chunk is authenticated on its own, and
its position and a "last chunk" flag are part of its nonce. This allows files of any size while still
detecting reordering, truncation and appended data.

## Not protected

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
- **Side channels in the platform.** Timing and cache behaviour of the underlying primitives are up to the OS
  libraries. Modern CPUs with AES instructions make AES-GCM constant-time.

## Limits

| Item | Limit |
| --- | --- |
| Messages per key | No practical limit (per-message keys). |
| In-memory message size | About 2 GB (.NET array limit). Use `Caltrop.Files` beyond that. |
| Stream size | No practical limit (2^64 chunks of 64 KiB). |
| Two-factor code window | One 30-second step either side of now. |

## Status

Caltrop has not yet been independently audited. Please review it, or have it reviewed, before you rely on it
for high-stakes data. Vulnerability reports are welcome; see [SECURITY.md](../SECURITY.md).

Releases are built and tested by GitHub Actions and come with SHA-256 checksums and a signed build provenance
attestation, so you can check that a `Caltrop.dll` you downloaded was built from this repository. See
[Verify a download](../README.md#verify-a-download).
