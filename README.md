<p align="center"><img src="assets/logo.png" alt="Caltrop logo" width="180"></p>

<h1 align="center">Caltrop</h1>

**Drop-in security for .NET.** Encrypt and decrypt, hash passwords, sign data, issue tokens, add two-factor
login and more, each in one line, with safe defaults and no security code to write.

```csharp
string secret = Caltrop.Encrypt("4111 1111 1111 1111", key);
string card   = Caltrop.Decrypt(secret, key);
```

- **One file, no dependencies.** Download `Caltrop.dll`, add it to your project, and you're done.
- **Works offline.** Caltrop never connects to the internet or starts other programs. A test fails the build
  if that ever changes.
- **One simple API.** Everything starts with `Caltrop.`, so IntelliSense shows you what's possible.
- **Safe by default.** Authenticated encryption everywhere, random nonces, constant-time comparisons and
  versioned formats. If data is tampered with, Caltrop throws instead of returning garbage.
- **Built on .NET's own cryptography** (OpenSSL on Linux, CNG on Windows, Apple's libraries on macOS).
  Trimming and Native AOT friendly.
- **Errors that tell you what to do**, for example: *"Wrong kind of Caltrop data: this is a message encrypted
  with a password. Use Caltrop.DecryptWithPassword(data, password)."*

## Install

Requires **.NET 10** or later.

1. Download [**Caltrop.dll**](../../releases/latest/download/Caltrop.dll) from the latest release. That one
   file is the whole library.
2. Put it in your project folder, for example in `libs/`.
3. Add these lines to your `.csproj`:

   ```xml
   <ItemGroup>
     <Reference Include="Caltrop" HintPath="libs/Caltrop.dll" />
     <Using Include="CaltropSecurity" />
   </ItemGroup>
   ```

   The `Using` line saves you writing `using CaltropSecurity;` at the top of every file.

In Visual Studio you can instead right-click **Dependencies**, choose **Add Project Reference**, then
**Browse**, pick the file, and add `using CaltropSecurity;` to your files.

Optional: download [Caltrop.xml](../../releases/latest/download/Caltrop.xml) too and put it next to the DLL to
see method descriptions in your editor. To check that a download is genuine, see
[Verify a download](#verify-a-download). To build the DLL yourself, see [Building from source](#building-from-source).

## Quick start

1. Create a key once, and keep it secret:

   ```csharp
   Console.WriteLine(CaltropKey.Generate().Export());   // ctk_4hT0...
   ```

2. Put it in the `CALTROP_KEY` environment variable, or in your secret manager.

3. Use it anywhere:

   ```csharp
   string secret = Caltrop.Encrypt("hello");   // uses CALTROP_KEY
   string plain  = Caltrop.Decrypt(secret);
   ```

Prefer explicit keys? Every method also takes one: `Caltrop.Encrypt("hello", key)`. To load the default key
from configuration instead, call `Caltrop.UseKey(CaltropKey.Parse(config["Caltrop:Key"]!))` when your app starts.

## What's in the box

| You want to | Use |
| --- | --- |
| Encrypt data for your database or files | `Caltrop.Encrypt` / `Caltrop.Decrypt` |
| Encrypt with a password (wallet seed phrases, private keys, notes) | `Caltrop.EncryptWithPassword` / `DecryptWithPassword` |
| Store user passwords | `Caltrop.Passwords.Hash` / `Verify` |
| Make password-reset links, invites, email verification | `Caltrop.Tokens` |
| Add two-factor login with authenticator apps | `Caltrop.TwoFactor` |
| Encrypt large files, streams and uploads | `Caltrop.Files` |
| Send data only one person can read, or sign data | `Caltrop.Encrypt(data, publicKey)`, `Caltrop.Sign` |
| Issue API keys for your own API | `Caltrop.ApiKeys` |
| Verify incoming webhooks or sign outgoing ones | `Caltrop.Webhooks` |
| Search encrypted columns | `Caltrop.Hashing.BlindIndex` |
| Hash, HMAC or checksum something | `Caltrop.Hashing` |
| Make secure random tokens, passwords and numbers | `Caltrop.Random` |
| Compare secrets without timing leaks | `Caltrop.SecureEquals` |

The [guide](docs/guide.md) covers every feature in depth, with ASP.NET Core and Entity Framework examples.

## Examples

### Encrypt and decrypt

```csharp
string encrypted = Caltrop.Encrypt(user.Ssn, key, context: $"user:{user.Id}");
string ssn       = Caltrop.Decrypt(encrypted, key, context: $"user:{user.Id}");
```

`context` is optional. It ties the encrypted value to something (here, the user), so a value copied to
another user's row will not decrypt. There are `byte[]` overloads too.

### Protect wallet keys and seed phrases

```csharp
string locked = Caltrop.EncryptWithPassword(seedPhrase, password);   // save this, never the seed phrase
string seed   = Caltrop.DecryptWithPassword(locked, password);       // when the user unlocks the wallet
```

A wrong password throws a `CaltropException` with `AuthenticationFailed`. The protection is only as strong as
the password, so ask for a long one. Caltrop protects wallet secrets. It doesn't create wallets or sign
blockchain transactions; use a dedicated library such as NBitcoin or Nethereum for that. The
[guide](docs/guide.md#wallet-secrets) has more.

### Rotate keys

```csharp
// CALTROP_KEY="ctk_new...,ctk_old..."   (newest first)
var keys = CaltropKeyRing.Parse(Environment.GetEnvironmentVariable("CALTROP_KEY")!);
string fresh = Caltrop.Encrypt("new data", keys.Primary);   // always the newest key
string old   = Caltrop.Decrypt(oldCiphertext, keys);         // any key in the ring
```

### Hash passwords

```csharp
user.PasswordHash = Caltrop.Passwords.Hash(password);   // sign-up

if (Caltrop.Passwords.Verify(password, user.PasswordHash))   // login
{
    if (Caltrop.Passwords.NeedsRehash(user.PasswordHash))
        user.PasswordHash = Caltrop.Passwords.Hash(password);   // upgrades old hashes over time
}
```

### Tokens for links

```csharp
string token = Caltrop.Tokens.Create(user.Id, key, TimeSpan.FromHours(1), purpose: "password-reset");
// email https://example.com/reset?token={token}

if (Caltrop.Tokens.TryValidate(token, key, out string? userId, purpose: "password-reset"))
{
    // genuine, unexpired, and made for password resets
}
```

### Two-factor login

```csharp
string secret = Caltrop.TwoFactor.CreateSecret();   // store it with the user (encrypted)
string setup  = Caltrop.TwoFactor.GetSetupUri(secret, user.Email, "My App");   // show as a QR code

bool ok = Caltrop.TwoFactor.Verify(secret, codeFromUser);
string[] recovery = Caltrop.TwoFactor.CreateRecoveryCodes();
```

### Files

```csharp
Caltrop.Files.EncryptFile("report.pdf", "report.pdf.caltrop", key);
Caltrop.Files.DecryptFile("report.pdf.caltrop", "report.pdf", key);

await Caltrop.Files.EncryptAsync(upload.OpenReadStream(), storageStream, key);
```

Files of any size are processed in chunks without loading them into memory, and a damaged file never leaves a
half-decrypted output behind.

### Public keys and signatures

```csharp
using var alice = CaltropKeyPair.Generate();
string publicKey = alice.PublicKey.Export();   // share freely: ctpub_...

string secret = Caltrop.Encrypt("for Alice only", CaltropPublicKey.Parse(publicKey));
string plain  = Caltrop.Decrypt(secret, alice);

string signature = Caltrop.Sign("release v1.2.0", alice);
bool genuine = Caltrop.VerifySignature("release v1.2.0", signature, alice.PublicKey);
```

### API keys and webhooks

```csharp
string apiKey = Caltrop.ApiKeys.Generate("acme_live");   // give to the customer once
customer.ApiKeyHash = Caltrop.ApiKeys.Hash(apiKey);      // store only this

bool fromGitHub = Caltrop.Webhooks.Verify(rawBody, request.Headers["X-Hub-Signature-256"], webhookSecret);
```

## Errors

When something is wrong, Caltrop throws a `CaltropException`. Its `ErrorCode` says why:

| `ErrorCode` | Meaning |
| --- | --- |
| `AuthenticationFailed` | The data was changed or damaged, or the key, password or context is wrong. |
| `KeyMismatch` | The data was encrypted with a different key (the message includes the key id). |
| `TokenExpired` | The token is genuine but too old. |
| `WrongDataType` | Real Caltrop data, but the wrong kind for this method. The message names the right one. |
| `InvalidFormat` | Not Caltrop data, or cut off. |
| `UnsupportedVersion` | Made by a newer version of Caltrop. Update the package. |
| `InvalidKey` | A key string could not be read or failed its checksum. |

`CaltropException` derives from `CryptographicException`. Mistakes in your own code, such as a `null`
argument, throw the usual `ArgumentException` types. Methods that check untrusted input, such as
`VerifySignature`, `Webhooks.Verify` and `Tokens.TryValidate`, return `false` instead of throwing.

## Keeping keys safe

- Generate keys with `CaltropKey.Generate()` and store `key.Export()` in a secret manager (Azure Key Vault,
  AWS Secrets Manager, Doppler, 1Password) or an environment variable. Never commit keys to source control.
- Anyone with a key can decrypt everything encrypted with it. Use different keys for different apps.
- Rotate keys by putting a new key first in the ring. Keep old keys until all old data has been re-encrypted.
- `CaltropKey.ToString()` only shows the key id, so logging a key object never leaks it.

## How it works

| Feature | Algorithm |
| --- | --- |
| `Encrypt` / `Decrypt`, tokens | AES-256-GCM with a fresh key for every message, derived with HKDF-SHA256 from a random 192-bit nonce |
| Password encryption and hashing | PBKDF2-HMAC-SHA256, 600,000 iterations, 128-bit random salt |
| Files and streams | AES-256-GCM in 64 KiB authenticated chunks (the STREAM construction) |
| Public-key encryption | ECIES on P-256: ephemeral ECDH, HKDF-SHA256, AES-256-GCM |
| Signatures | ECDSA P-256 with SHA-256 |
| Two-factor codes | TOTP (RFC 6238): HMAC-SHA1, 6 digits, 30 seconds |
| API key and recovery code storage | SHA-256 |
| Webhooks, blind indexes | HMAC-SHA256 |

Every output starts with a format version, so future versions can improve algorithms and still read old data.
The byte layouts are documented in [docs/format.md](docs/format.md), and the design and its limits in
[docs/security-model.md](docs/security-model.md).

## Project layout

```text
Caltrop/
├── src/Caltrop/              the library (builds Caltrop.dll)
│   ├── Caltrop.cs            Encrypt, Decrypt, password encryption, default key
│   ├── Caltrop.PublicKey.cs  public-key encryption and signatures
│   ├── Features/             Passwords, Tokens, TwoFactor, Files, ApiKeys, Webhooks, Hashing, Random
│   ├── Keys/                 CaltropKey, CaltropKeyRing, CaltropKeyPair, CaltropPublicKey
│   └── Internal/             wire formats and helpers (not public)
├── tests/Caltrop.Tests/      xUnit tests, including standard test vectors and format compatibility tests
├── samples/Caltrop.Samples/  a runnable tour of every feature
├── docs/                     guide, format specification, security model
├── assets/                   logo and package icon
└── .github/                  CI, release workflow, issue templates
```

## Building from source

```shell
dotnet build                                   # warnings are errors in the library
dotnet test                                    # runs the xUnit tests
dotnet run --project samples/Caltrop.Samples   # the feature tour
dotnet pack src/Caltrop -c Release -o artifacts
```

## Releasing

On GitHub, open **Actions**, choose **Release**, click **Run workflow** and enter a version such as `1.0.0`.
Pushing a tag such as `v1.0.0` does the same. The [release workflow](.github/workflows/release.yml) runs
every test, then publishes a GitHub release with:

| File | What it is |
| --- | --- |
| `Caltrop.dll` | The library, with its debug information built in |
| `Caltrop.xml` | Method descriptions for editors |
| `Caltrop.<version>.nupkg` | The same library as a NuGet package |
| `SHA256SUMS.txt` | Checksums of the files above |

The download links in [Install](#install) always point to the newest release. Publishing to nuget.org is
optional and off by default: it only happens if the repository has a `NUGET_API_KEY` secret.

## Verify a download

Every release is built and tested by GitHub Actions from the code in this repository, and GitHub keeps a
signed record of that build. To check a downloaded `Caltrop.dll`:

- **It is unchanged:** compare its SHA-256 with the one in the release notes. Run `Get-FileHash Caltrop.dll`
  in PowerShell on Windows, or `shasum -a 256 Caltrop.dll` on macOS and Linux.
- **It was built from this repository:** with the [GitHub CLI](https://cli.github.com), run
  `gh attestation verify Caltrop.dll --repo <owner>/Caltrop`. The release notes show the exact command.

## Security

Caltrop uses only the cryptographic primitives built into .NET and never implements its own. It has not yet
had an independent security audit. Please have it reviewed before you rely on it for high-stakes data, such
as wallets that hold real money.

To report a vulnerability, please follow [SECURITY.md](SECURITY.md) instead of opening a public issue.

## License

[MIT](LICENSE)
