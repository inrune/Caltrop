using System.Security.Cryptography;
using CaltropSecurity.Internal;

namespace CaltropSecurity.Tests;

// Caltrop checks P-256 points itself, so every operating system rejects bad keys the same way.
public class CurveTests
{
    // The P-256 base point G from SEC 2 / FIPS 186-5.
    private static readonly byte[] s_gx = Convert.FromHexString("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296");
    private static readonly byte[] s_gy = Convert.FromHexString("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5");

    [Fact]
    public void The_base_point_is_on_the_curve()
    {
        Assert.True(P256.IsOnCurve(s_gx, s_gy));
    }

    [Fact]
    public void A_changed_coordinate_is_not_on_the_curve()
    {
        byte[] y = (byte[])s_gy.Clone();
        y[^1] ^= 1;
        Assert.False(P256.IsOnCurve(s_gx, y));
    }

    [Fact]
    public void Coordinates_outside_the_field_are_rejected()
    {
        byte[] tooBig = Convert.FromHexString("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        Assert.False(P256.IsOnCurve(tooBig, s_gy));
        Assert.False(P256.IsOnCurve(s_gx, tooBig));
    }

    [Fact]
    public void Wrong_lengths_are_rejected()
    {
        Assert.False(P256.IsOnCurve(s_gx[1..], s_gy));
        Assert.False(P256.IsOnCurve(new ECPoint { X = s_gx, Y = null }));
    }

    [Fact]
    public void Freshly_generated_points_are_on_the_curve()
    {
        for (int i = 0; i < 20; i++)
        {
            using var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            Assert.True(P256.IsOnCurve(ecdh.ExportParameters(includePrivateParameters: false).Q));
        }
    }
}
