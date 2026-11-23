# Caltrop format specification (version 1)

This document describes every byte Caltrop produces, so the data can be read by other tools or languages and so
that future versions stay compatible. All integers are big-endian. Text forms use Base64Url (RFC 4648 §5)
without padding.

Each value has exactly one text form. Readers ignore whitespace around a value, but reject anything else that
would decode to the same bytes: whitespace or padding inside, a non-standard last character, uppercase hex where
Caltrop writes lowercase, or a number with leading zeros. So a changed text is never taken for the original.

## Common header

Every blob starts with two bytes:

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 1 | Format version, `0x01` |
| 1 | 1 | Kind (below) |

| Kind | Meaning | Made by |
| --- | --- | --- |
| `0x01` | Secret-key message | `Caltrop.Encrypt(…, CaltropKey)` |
| `0x02` | Password message | `Caltrop.EncryptWithPassword` |
| `0x03` | Public-key message | `Caltrop.Encrypt(…, CaltropPublicKey)` |
| `0x04` | Token | `Caltrop.Tokens.Create` |
| `0x05` | Secret-key stream | `Caltrop.Files.Encrypt*` |
| `0x06` | Password stream | `Caltrop.Files.EncryptWithPassword*` |
| `0x07` | Signature | `Caltrop.Sign` |

## Keys

### Secret keys (`ctk_`)

A key is 32 random bytes, *K*. Its **key id** is the first 4 bytes of HKDF-Expand(SHA-256, PRK = *K*,
info = `"caltrop/v1/key-id"`).

Every derived key below is HKDF-Expand(SHA-256, PRK = *K*, info = *label* ‖ *context*, length 32). The labels
are ASCII and none is a prefix of another:

| Label | Used for |
| --- | --- |
| `caltrop/v1/message:` | message keys (context: the 24-byte nonce) |
| `caltrop/v1/token:` | token keys (context: the 24-byte nonce) |
| `caltrop/v1/stream:` | file keys (context: the 24-byte nonce) |
| `caltrop/v1/blind-index:` | blind index keys (context: the UTF-8 purpose) |
| `caltrop/v1/decoy:` | decoy mark keys (context: `password-hash`, `api-key` or `message`) |
| `caltrop/v1/tamper:` | seal keys (context: one byte, `01` for content, `02` for folders) |
| `caltrop/v1/vault:` | vault master keys for key-locked vaults (context: `master`) |
| `caltrop/v1/log:` | log keys (no context) |

### Key strings

`ctk_`, `ctpub_` and `ctprv_` strings are *prefix* ‖ Base64Url(*payload* ‖ *checksum*), where *checksum* is
the first 4 bytes of SHA-256(ASCII(*prefix*) ‖ *payload*).

| Prefix | Payload |
| --- | --- |
| `ctk_` | *K* (32 bytes) |
| `ctpub_` | encryption public key X, Y ‖ signing public key X, Y (4 × 32 bytes) |
| `ctprv_` | the 128-byte public payload ‖ encryption private scalar ‖ signing private scalar (192 bytes) |

Caltrop's own key file, `caltrop.key`, holds a key string (or several, separated by commas, newest first)
followed by a new line.

A key pair holds two NIST P-256 keys: one for ECDH and one for ECDSA. Its key id is the first 4 bytes of
SHA-256 of the 128-byte public payload.

## Secret-key message (`0x01`)

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 2 | Header `01 01` |
| 2 | 4 | Key id |
| 6 | 24 | Nonce *N*, random |
| 30 | *n* | Ciphertext |
| 30 + *n* | 16 | GCM tag |

- Message key: HKDF-Expand(*K*, `"caltrop/v1/message:"` ‖ *N*).
- AES-256-GCM with the message key and the first 12 bytes of *N* as the GCM nonce.
- Associated data: bytes 0 to 29 ‖ the caller's context (UTF-8 for text overloads; empty if none).

Every message gets its own AES key, so the 96-bit GCM nonce never repeats under one key in practice. The
number of messages per Caltrop key is effectively unlimited.

## Password message (`0x02`)

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 2 | Header `01 02` |
| 2 | 4 | PBKDF2 iteration count |
| 6 | 16 | Salt, random |
| 22 | 12 | GCM nonce, random |
| 34 | *n* | Ciphertext |
| 34 + *n* | 16 | GCM tag |

- Key: PBKDF2-HMAC-SHA256(UTF-8 of the NFC-normalized password, salt, iterations, 32 bytes).
- AES-256-GCM; associated data: bytes 0 to 33.
- New data uses 600,000 iterations. Readers reject counts above 10,000,000.

## Public-key message (`0x03`)

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 2 | Header `01 03` |
| 2 | 4 | Recipient key id |
| 6 | 65 | Ephemeral P-256 public key *E*, uncompressed SEC1 (`04` ‖ X ‖ Y) |
| 71 | *n* | Ciphertext |
| 71 + *n* | 16 | GCM tag |

- *Z* = ECDH(ephemeral private key, recipient encryption key), the 32-byte X coordinate.
- 44 bytes = HKDF-SHA256(IKM = *Z*, salt = *E* ‖ recipient encryption key as uncompressed SEC1,
  info = `"caltrop/v1/seal"`). Bytes 0 to 31 are the AES-256-GCM key, bytes 32 to 43 the nonce.
- Associated data: bytes 0 to 70 ‖ the caller's context.
- Readers check that *E* is on the curve.

## Token (`0x04`)

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 2 | Header `01 04` |
| 2 | 4 | Key id |
| 6 | 24 | Nonce *N*, random |
| 30 | 8 | Issued at, Unix seconds |
| 38 | 8 | Expires at, Unix seconds |
| 46 | *n* | Encrypted payload (UTF-8) |
| 46 + *n* | 16 | GCM tag |

- Token key: HKDF-Expand(*K*, `"caltrop/v1/token:"` ‖ *N*); GCM nonce: the first 12 bytes of *N*.
- Associated data: bytes 0 to 45 ‖ UTF-8 of the purpose (empty if none).
- A token is valid while the current Unix time is less than *expires at*. Expiry is only checked after the tag
  has been verified.

## Streams (`0x05`, `0x06`)

Secret-key stream header (30 bytes):

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 2 | Header `01 05` |
| 2 | 4 | Key id |
| 6 | 24 | Nonce *N*, random |

File key: HKDF-Expand(*K*, `"caltrop/v1/stream:"` ‖ *N*).

Password stream header (22 bytes):

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 2 | Header `01 06` |
| 2 | 4 | PBKDF2 iteration count |
| 6 | 16 | Salt, random |

File key: PBKDF2-HMAC-SHA256(NFC password, salt, iterations, 32 bytes).

The header is followed by chunks. The plaintext is split into 64 KiB (65,536-byte) pieces; each is sealed with
AES-256-GCM under the file key and written as ciphertext ‖ 16-byte tag:

- GCM nonce for chunk *i* (counting from 0): `00 00 00` ‖ *i* as 8 bytes ‖ `01` for the final chunk, `00`
  otherwise.
- Associated data: the whole stream header.
- Every chunk except the last holds exactly 64 KiB of plaintext. The final chunk holds less, possibly
  nothing, so there is always a final chunk.

A reader treats a sealed chunk shorter than 65,552 bytes as the final one, and requires the stream to end
there. This detects reordered, dropped, truncated and appended chunks.

## Signature (`0x07`)

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 2 | Header `01 07` |
| 2 | 4 | Signer key id |
| 6 | 64 | ECDSA P-256 signature, *r* ‖ *s* (IEEE P1363) |

The signed digest is SHA-256(`"caltrop/v1/sign:"` ‖ message), signed with the key pair's signing key.

## Other formats

**Password hashes**: `$pbkdf2-sha256$i=<iterations>$<salt>$<hash>` in the PHC string format, where salt (16
bytes) and hash (32 bytes) are standard Base64 without padding, and the input is the NFC-normalized password as
UTF-8. Hashes from other tools are read too, with salts of 8 to 64 bytes; the hash must be 32 bytes.

**API keys**: `<prefix>_<32 Base62 characters><6 Base62 characters>`. The last six characters are the first 4
bytes of SHA-256(`<prefix>_<random part>`), read as a big-endian unsigned integer and written as exactly six Base62
digits (`0-9A-Za-z`), most significant first, padded with leading `0`. `ApiKeys.Hash` is SHA-256 of the whole key, as lowercase hex.

**Blind indexes**: HMAC-SHA256(key = HKDF-Expand(*K*, `"caltrop/v1/blind-index:"` ‖ purpose), UTF-8 value),
as lowercase hex.

**Webhooks**: `sha256=` ‖ hex(HMAC-SHA256(UTF-8 secret, body)). Timestamped:
`t=<unix seconds>,v1=<hex(HMAC-SHA256(UTF-8 secret, "<unix seconds>." ‖ body))>`.

## Vault (`0x08`)

A vault file is one blob. Byte 2 says how it is locked.

| Offset | Size | Field (locked with a password, mode `01`) |
| --- | --- | --- |
| 0 | 3 | Header `01 08 01` |
| 3 | 4 | PBKDF2 iteration count |
| 7 | 16 | Salt, random |
| 23 | 24 | Nonce *N*, random, new on every save |
| 47 | *n* | Ciphertext |
| 47 + *n* | 16 | GCM tag |

| Offset | Size | Field (locked with a key, mode `02`) |
| --- | --- | --- |
| 0 | 3 | Header `01 08 02` |
| 3 | 4 | Key id |
| 7 | 24 | Nonce *N*, random, new on every save |
| 31 | *n* | Ciphertext |
| 31 + *n* | 16 | GCM tag |

- Master key *M*: PBKDF2-HMAC-SHA256(NFC password, salt, iterations, 32 bytes), or
  HKDF-Expand(*K*, `"caltrop/v1/vault:master"`).
- File key: HKDF-Expand(PRK = *M*, info = `"caltrop/v1/vault:"` ‖ *N*); GCM nonce: the first 12 bytes of *N*;
  associated data: the whole header.
- The plaintext is: entry count (4), then for each entry in ordinal name order: name length (2), UTF-8 name,
  value length (4), value.
- Saving writes the whole file to a temporary file in the same folder, flushes it to disk and moves it into place.
  A writer first opens `<vault>.lock` exclusively, reads the file again if its nonce *N* is not the one it last
  saw (someone else saved since), makes its change and saves. Readers need no lock: they compare *N* and reload
  when it changed.

## Seals (`cts_`)

`cts_` strings use the key string encoding above, with a 37-byte payload: kind (1: `01` content, `02` folder) ‖
key id (4) ‖ MAC (32).

- Content seals: MAC = HMAC-SHA256(HKDF-Expand(*K*, `"caltrop/v1/tamper:"` ‖ `01`), content). A file seal is the
  content seal of the file's bytes.
- Folder seals: MAC = HMAC-SHA256(HKDF-Expand(*K*, `"caltrop/v1/tamper:"` ‖ `02`), entries), where the entries
  are every file under the folder (recursively, including hidden files) in ordinal order of their relative
  paths written with `/`. For each: UTF-8 path length (4) ‖ UTF-8 path ‖ SHA-256 of the contents.

## Caltrop.dll self-seal

Caltrop.dll contains the 16 bytes `c4 1a 7e 93 5b d2 08 f6 2c a1 6d 3f e8 47 b9 10` followed by a 32-byte slot.
After compiling, the build writes into the slot the SHA-256 of the whole file, computed with the slot zeroed
and, as Authenticode does, with the PE checksum, the certificate table directory entry and any certificate data
left out. `Tamper.CheckCaltrop` repeats the calculation on the loaded file.

## Decoy marks

A decoy hides a mark in what is normally random: mark = HMAC-SHA256(HKDF-Expand(*K*, `"caltrop/v1/decoy:"` ‖
*domain*), *data*), truncated.

| Decoy | Random part | Data | Mark |
| --- | --- | --- | --- |
| Password hash (`password-hash`) | 16-byte salt | first 8 bytes of the salt | last 8 bytes of the salt |
| API key (`api-key`) | 32 random characters | ASCII `<prefix>_<first 21 characters>` | last 11 characters: the first 8 MAC bytes as a big-endian integer in 11 Base62 digits |
| Encrypted value (`message`) | 24-byte nonce | first 12 bytes of the nonce | last 12 bytes of the nonce |

Decoy password hashes use 600,000 iterations and a random 32-byte hash that no password produces.

## Tamper-proof log

A UTF-8 text file. Line 1 is `# Caltrop log v1, key <key id as 8 hex digits>`. Every other line is one entry:

```text
<number>\t<time>\t<message>\t<check>
```

- *number* counts from 1. *time* is UTC, as `yyyy-MM-ddTHH:mm:ss.fffZ`.
- In *message*, `\`, tab, CR and LF are written as `\\`, `\t`, `\r` and `\n`, and other control characters as
  `\uXXXX`.
- *check* = Base64Url of the first 16 bytes of HMAC-SHA256(HKDF-Expand(*K*, `"caltrop/v1/log:"`),
  *previous check* ‖ UTF-8(`<number>\t<time>\t<message>`)), where the previous check of entry 1 is 16 zero bytes.
- `Head` is `<last number>:<last check>`.
- Lines end with LF; a CR before it is ignored. A writer first opens `<log>.lock` exclusively, then appends one
  whole line in a single write, chained to the last entry in the file. If the file does not end with LF (a line
  was cut off), the writer adds one first. Readers ignore a last line with no LF, which may still be being written.
