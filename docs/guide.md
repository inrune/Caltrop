# Caltrop guide

Everything Caltrop does, with examples. For a quick overview see the [README](../README.md).

- [Setup](#setup)
- [Encrypting data](#encrypting-data)
- [Key rotation](#key-rotation)
- [Password encryption](#password-encryption)
- [User passwords](#user-passwords)
- [Tokens](#tokens)
- [Two-factor authentication](#two-factor-authentication)
- [Files and streams](#files-and-streams)
- [Public keys and signatures](#public-keys-and-signatures)
- [API keys](#api-keys)
- [Webhooks](#webhooks)
- [Hashing and searching encrypted data](#hashing-and-searching-encrypted-data)
- [Random values](#random-values)
- [Errors and troubleshooting](#errors-and-troubleshooting)
- [Performance and thread safety](#performance-and-thread-safety)

## Setup

Add `Caltrop.dll` to your project as shown in the [README](../README.md#install). It needs .NET 10 or later
and works fully offline.

All types are in the `CaltropSecurity` namespace. Import it once for the whole project with
`<Using Include="CaltropSecurity" />` in your project file, as the README shows, or add `using CaltropSecurity;`
at the top of each file. If you use the NuGet package from a release instead, projects with implicit usings
turned on (the default) get the namespace automatically. To opt out, set
`<CaltropImplicitUsings>false</CaltropImplicitUsings>` in your project file.

### Creating and storing a key

```csharp
using var key = CaltropKey.Generate();
Console.WriteLine(key.Export());   // ctk_... (52 characters)
```

Store the exported text in a secret manager or an environment variable, never in source control. Load it with
`CaltropKey.Parse(text)`, which also accepts 32 random bytes as Base64 or hex, so keys made with
`openssl rand -base64 32` work too.

Each key has a short public `Id` (8 hex characters). It is stored with everything the key encrypts, so error
messages can tell you which key was expected. `key.ToString()` shows only the id, so logging a key is safe.

### The default key

Methods that take no key use `Caltrop.DefaultKeys`. It is read from the `CALTROP_KEY` environment variable the
first time it is needed. You can also set it yourself when your app starts. In ASP.NET Core:

```csharp
var builder = WebApplication.CreateBuilder(args);

// From configuration (user secrets, Key Vault, environment variables...)
Caltrop.UseKeys(CaltropKeyRing.Parse(builder.Configuration["Caltrop:Keys"]!));
```

After that, `Caltrop.Encrypt(text)`, `Caltrop.Decrypt(text)`, `Caltrop.Tokens.Create(payload, lifetime)` and
`Caltrop.Tokens.Validate(token)` work anywhere in the app. Caltrop keeps using the key objects you pass, so do
not dispose them while they are the default.

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

Never store or encrypt user passwords. Store a hash:

```csharp
// Sign-up
user.PasswordHash = Caltrop.Passwords.Hash(password);

// Login
if (Caltrop.Passwords.Verify(password, user.PasswordHash))
{
    if (Caltrop.Passwords.NeedsRehash(user.PasswordHash))
    {
        user.PasswordHash = Caltrop.Passwords.Hash(password);   // upgrade older hashes as people log in
    }
}
```

Hashes use the standard PHC format (`$pbkdf2-sha256$i=600000$salt$hash`), so other tools can read them.
Passwords are Unicode-normalized first, so `é` typed on a Mac and on Windows matches.

Tip: if no user has the given email, still verify against a dummy hash. Otherwise the faster response reveals
which emails are registered.

```csharp
static readonly string DummyHash = Caltrop.Passwords.Hash(Caltrop.Random.Token());

var user = await db.Users.SingleOrDefaultAsync(u => u.Email == email);
bool ok = Caltrop.Passwords.Verify(password, user?.PasswordHash ?? DummyHash) && user is not null;
```

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
- Tokens are stateless, so a token works until it expires, even after it has been used. For one-time links,
  put something in the payload that changes when the link is used, such as a security stamp that changes with
  the password, and check it:

```csharp
string token = Caltrop.Tokens.Create($"{user.Id}:{user.SecurityStamp}", key, TimeSpan.FromHours(1), "password-reset");
```

## Two-factor authentication

Codes from authenticator apps (TOTP, RFC 6238).

### Enrolling a user

```csharp
string secret = Caltrop.TwoFactor.CreateSecret();
string setupUri = Caltrop.TwoFactor.GetSetupUri(secret, user.Email, "My App");
// Show setupUri as a QR code (any QR library, for example QRCoder), and the secret for manual entry.
// Store the secret encrypted: Caltrop.Encrypt(secret, key, context: $"totp:{user.Id}")
```

Ask for one code before turning 2FA on, so you know the user's app is set up.

### Checking a code

```csharp
bool ok = Caltrop.TwoFactor.Verify(secret, code);
```

Codes are accepted from 30 seconds before to 30 seconds after the current window, to allow for clock drift.
Spaces and dashes are ignored.

To make every code single-use, which RFC 6238 recommends, store the last time step:

```csharp
if (Caltrop.TwoFactor.Verify(secret, code, user.LastTotpStep, out long usedStep))
{
    user.LastTotpStep = usedStep;   // the same code, or an older one, will now be refused
}
```

### Recovery codes

```csharp
string[] codes = Caltrop.TwoFactor.CreateRecoveryCodes();   // show once, e.g. "7KQ2-M9HC-DX4P-T8WN"
user.RecoveryCodeHashes = [.. codes.Select(Caltrop.TwoFactor.HashRecoveryCode)];

// When one is used
string hash = Caltrop.TwoFactor.HashRecoveryCode(input);   // ignores case, spaces and dashes
if (user.RecoveryCodeHashes.Remove(hash))
{
    // signed in, and that code can never be used again
}
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

| What you see | Usual cause | Fix |
| --- | --- | --- |
| `KeyMismatch`: "encrypted with a different key (key id ...)" | The wrong key is loaded, for example a development key in production. | Compare `key.Id` with the id in the message. During rotation, use a key ring that includes the old key. |
| `AuthenticationFailed` | The data was changed, or the context, purpose or password differs. | Check that the context or purpose is exactly the same as when encrypting. |
| `InvalidFormat`: "too short" | The value was cut off, often by a database column that is too small. | Make the column bigger (see the size table above). |
| `WrongDataType` | A method was given another kind of Caltrop data. | Use the method the message names. |
| `TokenExpired` | The token is older than its lifetime. | Ask the user to request a new link. |
| `InvalidOperationException`: "No default Caltrop key is set" | `CALTROP_KEY` is not set and `UseKey` was not called. | Set the variable or call `Caltrop.UseKey` at startup. |
| `PlatformNotSupportedException` | The platform has no AES-GCM, for example Blazor WebAssembly. | Run Caltrop on the server. |

## Performance and thread safety

- Every `Caltrop` method is thread-safe, and key objects are immutable, so share them freely.
- Encryption runs at hardware AES speed, typically more than 1 GB/s. Each message derives its own key, which
  adds about a microsecond.
- Password hashing and password encryption are slow on purpose (roughly 0.1 to 0.5 seconds). Rate-limit login
  endpoints.
- `Dispose` on keys wipes them from memory. It is optional, and only safe once nothing else uses the key.
