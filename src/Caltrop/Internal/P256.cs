using System.Numerics;
using System.Security.Cryptography;

namespace CaltropSecurity.Internal;

/// <summary>
/// Checks NIST P-256 public points before they reach the platform. Every operating system rejects bad points on
/// import, but with different exception types (Windows throws <see cref="PlatformNotSupportedException"/>), so
/// Caltrop checks first and reports the same <see cref="CaltropException"/> everywhere.
/// </summary>
internal static class P256
{
    // Curve y² = x³ - 3x + b over the prime field p (SEC 2 / FIPS 186-5).
    private static readonly BigInteger s_p = Parse("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff");
    private static readonly BigInteger s_b = Parse("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b");

    /// <summary>True if (x, y), as 32-byte big-endian coordinates, is a point on the curve.</summary>
    public static bool IsOnCurve(ReadOnlySpan<byte> x, ReadOnlySpan<byte> y)
    {
        if (x.Length != Format.P256CoordinateSize || y.Length != Format.P256CoordinateSize)
        {
            return false;
        }

        var bx = new BigInteger(x, isUnsigned: true, isBigEndian: true);
        var by = new BigInteger(y, isUnsigned: true, isBigEndian: true);
        if (bx >= s_p || by >= s_p)
        {
            return false;
        }

        BigInteger left = by * by % s_p;
        BigInteger right = ((bx * bx % s_p * bx) - (3 * bx) + s_b) % s_p;
        if (right.Sign < 0)
        {
            right += s_p;
        }

        return left == right;
    }

    /// <summary>True if <paramref name="point"/> is a valid <see cref="ECPoint"/> on the curve.</summary>
    public static bool IsOnCurve(ECPoint point) => point.X is not null && point.Y is not null && IsOnCurve(point.X, point.Y);

    private static BigInteger Parse(string hex) => new(Convert.FromHexString(hex), isUnsigned: true, isBigEndian: true);
}
