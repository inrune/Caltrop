using System.Security.Cryptography;
using System.Text;

namespace CaltropSecurity.Internal;

/// <summary>PBKDF2-HMAC-SHA256 over the NFC-normalized password.</summary>
internal static class PasswordKdf
{
    /// <summary>OWASP's 2023+ recommendation for PBKDF2-HMAC-SHA256.</summary>
    public const int DefaultIterations = 600_000;

    /// <summary>Lowest count accepted when creating new hashes or ciphertexts.</summary>
    public const int MinimumIterations = 100_000;

    /// <summary>Highest count accepted when reading data, so a malicious header cannot stall the process.</summary>
    public const int MaximumIterations = 10_000_000;

    public const int SaltSize = 16;

    public static void Derive(string password, ReadOnlySpan<byte> salt, int iterations, Span<byte> output) =>
        Rfc2898DeriveBytes.Pbkdf2(Normalize(password), salt, output, iterations, HashAlgorithmName.SHA256);

    public static void ValidateNewPassword(string password, string parameterName)
    {
        ArgumentNullException.ThrowIfNull(password, parameterName);
        if (password.Length == 0)
        {
            throw new ArgumentException("The password must not be empty.", parameterName);
        }
    }

    public static void ValidateIterations(int iterations, string parameterName)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(iterations, MinimumIterations, parameterName);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(iterations, MaximumIterations, parameterName);
    }

    /// <summary>
    /// The same password typed on different systems can arrive in different Unicode forms (for example "é" as one
    /// code point or as "e" plus an accent). Normalizing to NFC makes them hash the same.
    /// </summary>
    private static string Normalize(string password)
    {
        try
        {
            return password.IsNormalized(NormalizationForm.FormC) ? password : password.Normalize(NormalizationForm.FormC);
        }
        catch (ArgumentException)
        {
            return password; // invalid UTF-16 (lone surrogates) cannot be normalized; use it as-is
        }
    }
}
