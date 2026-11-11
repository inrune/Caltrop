// A quick tour of Caltrop. Run it with:  dotnet run --project samples/Caltrop.Samples
using CaltropSecurity;

// ------------------------------------------------------------------ keys
Section("Keys");
using var key = CaltropKey.Generate();
string exported = key.Export();
Console.WriteLine($"New key {key} exported as {exported[..10]}... (store it in a secret manager, never in code)");
using var sameKey = CaltropKey.Parse(exported);

// ------------------------------------------------------------------ encrypt / decrypt
Section("Encrypt and decrypt");
string secret = Caltrop.Encrypt("4111 1111 1111 1111", key);
Console.WriteLine($"Encrypted: {secret}");
Console.WriteLine($"Decrypted: {Caltrop.Decrypt(secret, sameKey)}");

// The default key: set CALTROP_KEY or call UseKey once, then skip the key argument everywhere.
Caltrop.UseKey(key);
Console.WriteLine($"With the default key: {Caltrop.Decrypt(Caltrop.Encrypt("no key argument needed"))}");

// Tampering is always detected.
try
{
    Caltrop.Decrypt(secret[..^2] + (secret[^2] == 'A' ? "B" : "A") + secret[^1], key);
}
catch (CaltropException ex)
{
    Console.WriteLine($"Tampered data rejected: {ex.ErrorCode}");
}

// ------------------------------------------------------------------ key rotation
Section("Key rotation");
using var newKey = CaltropKey.Generate();
var ring = new CaltropKeyRing(newKey, key); // newest first
Console.WriteLine($"Old data still decrypts with the ring: {Caltrop.Decrypt(secret, ring)}");

// ------------------------------------------------------------------ passwords
Section("Password hashing");
string hash = Caltrop.Passwords.Hash("hunter2");
Console.WriteLine($"Stored hash: {hash}");
Console.WriteLine($"Correct password: {Caltrop.Passwords.Verify("hunter2", hash)}, wrong password: {Caltrop.Passwords.Verify("hunter3", hash)}");

Section("Password encryption");
string diary = Caltrop.EncryptWithPassword("Dear diary...", "correct horse battery staple");
Console.WriteLine($"Decrypted with the password: {Caltrop.DecryptWithPassword(diary, "correct horse battery staple")}");

// ------------------------------------------------------------------ public keys
Section("Public-key encryption and signatures");
using var alice = CaltropKeyPair.Generate();
Console.WriteLine($"Alice shares her public key: {alice.PublicKey.Export()[..20]}...");
string forAlice = Caltrop.Encrypt("only Alice can read this", alice.PublicKey);
Console.WriteLine($"Alice decrypts: {Caltrop.Decrypt(forAlice, alice)}");
string signature = Caltrop.Sign("release v1.0.0", alice);
Console.WriteLine($"Signature valid: {Caltrop.VerifySignature("release v1.0.0", signature, alice.PublicKey)}, "
    + $"for a changed message: {Caltrop.VerifySignature("release v6.6.6", signature, alice.PublicKey)}");

// ------------------------------------------------------------------ tokens
Section("Tokens");
string token = Caltrop.Tokens.Create("user-42", key, TimeSpan.FromHours(1), purpose: "password-reset");
Console.WriteLine($"Reset link: https://example.com/reset?token={token}");
if (Caltrop.Tokens.TryValidate(token, key, out string? userId, purpose: "password-reset"))
{
    Console.WriteLine($"Token is valid for {userId}");
}

// ------------------------------------------------------------------ two-factor
Section("Two-factor authentication");
string totpSecret = Caltrop.TwoFactor.CreateSecret();
Console.WriteLine($"Show this as a QR code: {Caltrop.TwoFactor.GetSetupUri(totpSecret, "alice@example.com", "Caltrop Demo")}");
string code = Caltrop.TwoFactor.GetCode(totpSecret); // what the user's authenticator app shows now
Console.WriteLine($"Code {code} accepted: {Caltrop.TwoFactor.Verify(totpSecret, code)}");
Console.WriteLine($"Recovery codes: {string.Join(", ", Caltrop.TwoFactor.CreateRecoveryCodes(3))}");

// ------------------------------------------------------------------ files
Section("Files");
string folder = Directory.CreateTempSubdirectory("caltrop-demo-").FullName;
string original = Path.Combine(folder, "report.txt");
File.WriteAllText(original, "Quarterly numbers: up and to the right.");
Caltrop.Files.EncryptFile(original, original + ".caltrop", key);
Caltrop.Files.DecryptFile(original + ".caltrop", Path.Combine(folder, "restored.txt"), key);
Console.WriteLine($"Restored file says: {File.ReadAllText(Path.Combine(folder, "restored.txt"))}");
Directory.Delete(folder, recursive: true);

// ------------------------------------------------------------------ API keys
Section("API keys");
string apiKey = Caltrop.ApiKeys.Generate("demo_live");
string apiKeyHash = Caltrop.ApiKeys.Hash(apiKey); // store only this
Console.WriteLine($"Give the customer: {apiKey}");
Console.WriteLine($"Well formed: {Caltrop.ApiKeys.IsWellFormed(apiKey, "demo_live")}, matches stored hash: {Caltrop.ApiKeys.Verify(apiKey, apiKeyHash)}");

// ------------------------------------------------------------------ webhooks
Section("Webhooks");
string webhookSecret = Caltrop.Webhooks.CreateSecret();
string body = """{"event":"invoice.paid","amount":4200}""";
string header = Caltrop.Webhooks.SignWithTimestamp(body, webhookSecret);
Console.WriteLine($"Signature header: {header}");
Console.WriteLine($"Receiver accepts it: {Caltrop.Webhooks.VerifyWithTimestamp(body, header, webhookSecret)}");

// ------------------------------------------------------------------ hashing and random
Section("Hashing and random values");
Console.WriteLine($"SHA-256 of \"abc\": {Caltrop.Hashing.Sha256("abc")}");
Console.WriteLine($"Blind index for searching encrypted emails: {Caltrop.Hashing.BlindIndex("alice@example.com", key, "users.email")[..16]}...");
Console.WriteLine($"Session id: {Caltrop.Random.Token()}");
Console.WriteLine($"Generated password: {Caltrop.Random.Password()}");
Console.WriteLine($"Dice roll: {Caltrop.Random.Number(1, 7)}");

Console.WriteLine("\nDone.");

static void Section(string title) => Console.WriteLine($"\n== {title} ==");
