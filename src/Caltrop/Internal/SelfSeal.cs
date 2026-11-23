using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

namespace CaltropSecurity.Internal;

/// <summary>
/// Checks that Caltrop.dll on disk is exactly the file its build produced. The build (SelfSeal.targets) writes the
/// SHA-256 of the DLL into <see cref="Slot"/>; this class recomputes it the same way.
/// </summary>
internal static class SelfSeal
{
    public const int HashSize = 32;

    // A 16-byte marker, then a 32-byte slot the build fills in. The marker appears nowhere else in Caltrop.dll.
    private static ReadOnlySpan<byte> Data =>
    [
        0xC4, 0x1A, 0x7E, 0x93, 0x5B, 0xD2, 0x08, 0xF6, 0x2C, 0xA1, 0x6D, 0x3F, 0xE8, 0x47, 0xB9, 0x10,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];

    public static ReadOnlySpan<byte> Marker => Data[..16];

    /// <summary>The hash written into the loaded copy of Caltrop.dll by its build. All zeros if it was never sealed.</summary>
    public static ReadOnlySpan<byte> Slot => Data[16..];

    public static CaltropIntegrity Check(out string? path)
    {
        path = LoadedFrom();
        if (string.IsNullOrEmpty(path))
        {
            return CaltropIntegrity.CannotCheck;
        }

        byte[] file;
        try
        {
            file = File.ReadAllBytes(path);
        }
        catch (IOException)
        {
            return CaltropIntegrity.CannotCheck;
        }
        catch (UnauthorizedAccessException)
        {
            return CaltropIntegrity.CannotCheck;
        }

        return Verify(file, Slot);
    }

    /// <summary>Checks a copy of Caltrop.dll against the hash it is expected to carry.</summary>
    public static CaltropIntegrity Verify(byte[] file, ReadOnlySpan<byte> expected)
    {
        int slot = FindSlot(file);
        if (slot < 0 || !expected.ContainsAnyExcept((byte)0) || !file.AsSpan(slot, HashSize).SequenceEqual(expected))
        {
            return CaltropIntegrity.Changed;
        }

        return CryptographicOperations.FixedTimeEquals(ComputeHash(file, slot), expected) ? CaltropIntegrity.Intact : CaltropIntegrity.Changed;
    }

    /// <summary>Offset of the slot, or -1 unless the marker appears exactly once.</summary>
    public static int FindSlot(ReadOnlySpan<byte> file)
    {
        int first = file.IndexOf(Marker);
        if (first < 0 || file[(first + 1)..].IndexOf(Marker) >= 0)
        {
            return -1;
        }

        int slot = first + Marker.Length;
        return slot + HashSize <= file.Length ? slot : -1;
    }

    /// <summary>SHA-256 of the file with the slot, PE checksum, certificate table entry and certificate data left out.</summary>
    public static byte[] ComputeHash(byte[] file, int slot)
    {
        byte[] copy = (byte[])file.Clone();
        copy.AsSpan(slot, HashSize).Clear();
        long certStart = 0, certLength = 0;
        int pe = copy.Length >= 0x40 ? BinaryPrimitives.ReadInt32LittleEndian(copy.AsSpan(0x3C)) : -1;
        if (pe > 0 && pe + 24 + 240 <= copy.Length && copy.AsSpan(pe, 4).SequenceEqual("PE\0\0"u8))
        {
            int optional = pe + 24;
            bool plus = BinaryPrimitives.ReadUInt16LittleEndian(copy.AsSpan(optional)) == 0x20B;
            copy.AsSpan(optional + 64, 4).Clear();
            int directories = optional + (plus ? 112 : 96);
            if (BinaryPrimitives.ReadInt32LittleEndian(copy.AsSpan(directories - 4)) > 4)
            {
                int entry = directories + 32;
                certStart = BinaryPrimitives.ReadUInt32LittleEndian(copy.AsSpan(entry));
                certLength = BinaryPrimitives.ReadUInt32LittleEndian(copy.AsSpan(entry + 4));
                copy.AsSpan(entry, 8).Clear();
            }
        }

        using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        if (certLength > 0 && certStart + certLength <= copy.Length)
        {
            sha.AppendData(copy.AsSpan(0, (int)certStart));
            sha.AppendData(copy.AsSpan((int)(certStart + certLength)));
        }
        else
        {
            sha.AppendData(copy);
        }

        return sha.GetHashAndReset();
    }

    [UnconditionalSuppressMessage("SingleFile", "IL3000", Justification = "An empty location (single-file or Native AOT apps) is reported as CannotCheck.")]
    private static string LoadedFrom() => typeof(SelfSeal).Assembly.Location;
}
