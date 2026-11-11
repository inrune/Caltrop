# Caltrop

**Drop-in security for .NET.** Encrypt and decrypt, hash passwords, sign data, issue tokens, add two-factor
login and more, each in one line, with safe defaults and no security code to write. No dependencies: built
only on .NET's own cryptography.

```csharp
var key = CaltropKey.Generate();          // store key.Export() in a secret manager

string secret = Caltrop.Encrypt("4111 1111 1111 1111", key);
string card   = Caltrop.Decrypt(secret, key);
```

Set the `CALTROP_KEY` environment variable and you can leave the key out: `Caltrop.Encrypt("hello")`.

## Features

| You want to | Use |
| --- | --- |
| Encrypt data for your database or files | `Caltrop.Encrypt` / `Caltrop.Decrypt` |
| Encrypt with a password | `Caltrop.EncryptWithPassword` |
| Store user passwords | `Caltrop.Passwords.Hash` / `Verify` |
| Make password-reset links and invites | `Caltrop.Tokens` |
| Add two-factor login with authenticator apps | `Caltrop.TwoFactor` |
| Encrypt large files, streams and uploads | `Caltrop.Files` |
| Encrypt for a public key, sign and verify | `Caltrop.Encrypt(data, publicKey)`, `Caltrop.Sign` |
| Issue API keys | `Caltrop.ApiKeys` |
| Verify or sign webhooks | `Caltrop.Webhooks` |
| Search encrypted columns, hash, HMAC | `Caltrop.Hashing` |
| Secure random tokens, passwords and numbers | `Caltrop.Random` |

Encryption is authenticated (AES-256-GCM): tampered data throws a `CaltropException` instead of returning
wrong results. Every output is versioned so future releases can still read it.

Requires .NET 10 or later. Projects with implicit usings get `using CaltropSecurity;` automatically.

The full guide, format specification and security model are in the source repository.
