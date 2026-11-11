using System.Security.Cryptography;

namespace CaltropSecurity.Tests;

internal static class TestData
{
    public static byte[] RandomBytes(int length) => RandomNumberGenerator.GetBytes(length);

    /// <summary>Returns a copy of <paramref name="data"/> with one bit flipped at <paramref name="index"/>.</summary>
    public static byte[] FlipBit(byte[] data, int index, int bit = 0)
    {
        byte[] copy = (byte[])data.Clone();
        copy[index] ^= (byte)(1 << bit);
        return copy;
    }

    public static CaltropException Throws(CaltropErrorCode expected, Action action)
    {
        CaltropException ex = Assert.Throws<CaltropException>(action);
        Assert.Equal(expected, ex.ErrorCode);
        return ex;
    }

    public static CaltropException Throws(CaltropErrorCode expected, Func<object?> action)
    {
        CaltropException ex = Assert.Throws<CaltropException>(action);
        Assert.Equal(expected, ex.ErrorCode);
        return ex;
    }

    public const string Base64UrlPattern = "^[A-Za-z0-9_-]+$";
}
