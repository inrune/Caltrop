using System.Security.Cryptography;
using System.Text;

namespace CaltropSecurity.Tests;

public class WebhookTests
{
    // The example from GitHub's "Validating webhook deliveries" documentation.
    private const string GitHubSecret = "It's a Secret to Everybody";
    private const string GitHubPayload = "Hello, World!";
    private const string GitHubSignature = "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17";

    private static readonly DateTimeOffset s_now = new(2026, 11, 10, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Sign_matches_GitHubs_documented_example()
    {
        Assert.Equal(GitHubSignature, Caltrop.Webhooks.Sign(GitHubPayload, GitHubSecret));
        Assert.Equal(GitHubSignature, Caltrop.Webhooks.Sign(Encoding.UTF8.GetBytes(GitHubPayload), GitHubSecret));
    }

    [Fact]
    public void Verify_accepts_the_common_signature_formats()
    {
        byte[] mac = HMACSHA256.HashData(Encoding.UTF8.GetBytes(GitHubSecret), Encoding.UTF8.GetBytes(GitHubPayload));
        string hex = Convert.ToHexStringLower(mac);
        string[] formats =
        [
            GitHubSignature,
            hex,
            hex.ToUpperInvariant(),
            "SHA256=" + hex,
            $"  {GitHubSignature}  ",
            Convert.ToBase64String(mac),                                                  // Shopify style
            Convert.ToBase64String(mac).TrimEnd('=').Replace('+', '-').Replace('/', '_'), // Base64Url
        ];

        foreach (string signature in formats)
        {
            Assert.True(Caltrop.Webhooks.Verify(GitHubPayload, signature, GitHubSecret), signature);
        }
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("sha256=")]
    [InlineData("sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e18")]
    [InlineData("sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e1")]
    [InlineData("sha1=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17")]
    [InlineData("nonsense")]
    public void Verify_rejects_wrong_or_malformed_signatures(string? signature)
    {
        Assert.False(Caltrop.Webhooks.Verify(GitHubPayload, signature, GitHubSecret));
    }

    [Fact]
    public void Verify_rejects_a_changed_payload_or_secret()
    {
        Assert.False(Caltrop.Webhooks.Verify("Hello, World?", GitHubSignature, GitHubSecret));
        Assert.False(Caltrop.Webhooks.Verify(GitHubPayload, GitHubSignature, "another secret"));
    }

    [Fact]
    public void Timestamped_signatures_verify_within_the_tolerance()
    {
        byte[] body = Encoding.UTF8.GetBytes("{\"event\":\"paid\"}");
        string signature = Caltrop.Webhooks.SignWithTimestamp(body, "whsec_test", s_now);

        Assert.Matches("^t=[0-9]+,v1=[0-9a-f]{64}$", signature);
        Assert.True(Caltrop.Webhooks.VerifyWithTimestamp(body, signature, "whsec_test", TimeSpan.FromMinutes(5), s_now.AddMinutes(4)));
        Assert.False(Caltrop.Webhooks.VerifyWithTimestamp(body, signature, "whsec_test", TimeSpan.FromMinutes(5), s_now.AddMinutes(6)));
        Assert.False(Caltrop.Webhooks.VerifyWithTimestamp(body, signature, "whsec_test", TimeSpan.FromMinutes(5), s_now.AddMinutes(-6)));
    }

    [Fact]
    public void The_public_timestamp_api_round_trips()
    {
        string signature = Caltrop.Webhooks.SignWithTimestamp("body", "secret");

        Assert.True(Caltrop.Webhooks.VerifyWithTimestamp("body", signature, "secret"));
        Assert.False(Caltrop.Webhooks.VerifyWithTimestamp("body!", signature, "secret"));
    }

    [Fact]
    public void Changing_the_timestamp_breaks_the_signature()
    {
        byte[] body = [1, 2, 3];
        string signature = Caltrop.Webhooks.SignWithTimestamp(body, "s", s_now);
        long t = s_now.ToUnixTimeSeconds();
        string moved = signature.Replace($"t={t}", $"t={t + 60}", StringComparison.Ordinal);

        Assert.False(Caltrop.Webhooks.VerifyWithTimestamp(body, moved, "s", TimeSpan.FromMinutes(5), s_now));
    }

    [Fact]
    public void Any_matching_v1_entry_is_accepted()
    {
        byte[] body = [1, 2, 3];
        string signature = Caltrop.Webhooks.SignWithTimestamp(body, "new-secret", s_now);
        string withOld = signature.Replace(",v1=", $",v1={new string('0', 64)},v1=", StringComparison.Ordinal);

        Assert.True(Caltrop.Webhooks.VerifyWithTimestamp(body, withOld, "new-secret", TimeSpan.FromMinutes(5), s_now));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("v1=abc")]
    [InlineData("t=1793361600")]
    [InlineData("t=abc,v1=0000000000000000000000000000000000000000000000000000000000000000")]
    public void Malformed_timestamped_signatures_are_rejected(string? signature)
    {
        Assert.False(Caltrop.Webhooks.VerifyWithTimestamp([1], signature, "s", TimeSpan.FromMinutes(5), s_now));
    }

    [Fact]
    public void New_secrets_are_random_and_prefixed()
    {
        string secret = Caltrop.Webhooks.CreateSecret();

        Assert.Matches("^whsec_[A-Za-z0-9_-]{43}$", secret);
        Assert.NotEqual(secret, Caltrop.Webhooks.CreateSecret());
    }

    [Fact]
    public void An_empty_secret_is_rejected()
    {
        Assert.ThrowsAny<ArgumentException>(() => Caltrop.Webhooks.Sign("x", ""));
        Assert.ThrowsAny<ArgumentException>(() => Caltrop.Webhooks.Verify("x", "sig", null!));
    }
}
