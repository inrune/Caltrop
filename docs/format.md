# Caltrop format specification (version 1)

This document describes every byte Caltrop produces, so the data can be read by other tools or languages and so
that future versions stay compatible. All integers are big-endian. Text forms use Base64Url (RFC 4648 §5)
without padding.

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

### Key strings

`ctk_`, `ctpub_` and `ctprv_` strings are *prefix* ‖ Base64Url(*payload* ‖ *checksum*), where *checksum* is
the first 4 bytes of SHA-256(ASCII(*prefix*) ‖ *payload*).

| Prefix | Payload |
| --- | --- |
| `ctk_` | *K* (32 bytes) |
| `ctpub_` | encryption public key X, Y ‖ signing public key X, Y (4 × 32 bytes) |
| `ctprv_` | the 128-byte public payload ‖ encryption private scalar ‖ signing private scalar (192 bytes) |

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
bytes) and hash (32 bytes) are standard Base64 without padding, and the input is the NFC-normalized password.

**API keys**: `<prefix>_<32 Base62 characters><6 Base62 characters>`. The last six characters are the first 4
bytes of SHA-256(`<prefix>_<random part>`), read as a big-endian unsigned integer and written as exactly six Base62
digits (`0-9A-Za-z`), most significant first, padded with leading `0`. `ApiKeys.Hash` is SHA-256 of the whole key, as lowercase hex.

**Blind indexes**: HMAC-SHA256(key = HKDF-Expand(*K*, `"caltrop/v1/blind-index:"` ‖ purpose), UTF-8 value),
as lowercase hex.

**TOTP**: RFC 6238 with HMAC-SHA1, 6 digits and 30-second steps. Secrets are 20 random bytes in Base32 (RFC
4648) without padding. Recovery codes are 16 characters from `23456789ABCDEFGHJKMNPQRSTUVWXYZ`, grouped by four
with dashes; `HashRecoveryCode` is SHA-256 of the code upper-cased with spaces and dashes removed, as lowercase
hex.

**Webhooks**: `sha256=` ‖ hex(HMAC-SHA256(UTF-8 secret, body)). Timestamped:
`t=<unix seconds>,v1=<hex(HMAC-SHA256(UTF-8 secret, "<unix seconds>." ‖ body))>`.
