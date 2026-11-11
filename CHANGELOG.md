# Changelog

All notable changes to Caltrop are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.0.0]

First release.

### Added

- `Caltrop.Encrypt` / `Caltrop.Decrypt` for text and bytes, with AES-256-GCM, a fresh key per message and
  optional context binding.
- A default key, read from the `CALTROP_KEY` environment variable or set with `Caltrop.UseKey`.
- Key rotation with `CaltropKeyRing`.
- Password encryption (`EncryptWithPassword` / `DecryptWithPassword`) with PBKDF2-HMAC-SHA256.
- Public-key encryption and ECDSA signatures with `CaltropKeyPair` and `CaltropPublicKey`.
- `Caltrop.Passwords`: password hashing in PHC format, with `NeedsRehash`.
- `Caltrop.Tokens`: encrypted, expiring tokens with purposes.
- `Caltrop.TwoFactor`: TOTP codes, setup links, replay protection and recovery codes.
- `Caltrop.Files`: chunked encryption of streams and files, sync and async.
- `Caltrop.ApiKeys`: API keys with checksums, plus storage hashes.
- `Caltrop.Webhooks`: HMAC-SHA256 signing and verification, with optional timestamps.
- `Caltrop.Hashing`: SHA-256, SHA-512, HMAC-SHA256 and blind indexes.
- `Caltrop.Random`: secure bytes, numbers, strings, tokens and passwords.
- `Caltrop.SecureEquals` for constant-time comparisons.
- Works fully offline: no network calls and no other programs started, enforced by `OfflineTests`.
- Releases ship `Caltrop.dll` as a single file (debug information embedded), plus `Caltrop.xml`, a NuGet
  package, SHA-256 checksums and a signed GitHub build provenance attestation.
