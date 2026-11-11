using System.Collections;

namespace CaltropSecurity;

/// <summary>
/// A set of keys for key rotation: encrypt with the newest key (<see cref="Primary"/>) and still decrypt anything
/// made with the older ones. Pass the ring anywhere Caltrop accepts <c>IEnumerable&lt;CaltropKey&gt;</c>.
/// </summary>
/// <example>
/// <code>
/// // CALTROP_KEYS = "ctk_new...,ctk_old..."   (newest first)
/// var ring = CaltropKeyRing.Parse(Environment.GetEnvironmentVariable("CALTROP_KEYS")!);
/// string secret = Caltrop.Encrypt("data", ring.Primary);
/// string plain  = Caltrop.Decrypt(oldSecret, ring);   // works for data from any key in the ring
/// </code>
/// </example>
public sealed class CaltropKeyRing : IReadOnlyList<CaltropKey>
{
    private readonly CaltropKey[] _keys;

    /// <summary>Creates a ring. The first key is the primary key; the rest are older keys kept for decryption.</summary>
    /// <param name="primary">The key used for new encryption.</param>
    /// <param name="previousKeys">Older keys, still accepted when decrypting.</param>
    public CaltropKeyRing(CaltropKey primary, params CaltropKey[] previousKeys)
    {
        ArgumentNullException.ThrowIfNull(primary);
        ArgumentNullException.ThrowIfNull(previousKeys);
        _keys = [primary, .. previousKeys];
        foreach (CaltropKey key in _keys)
        {
            ArgumentNullException.ThrowIfNull(key, nameof(previousKeys));
        }
    }

    /// <summary>The newest key. Use it for all new encryption and tokens.</summary>
    public CaltropKey Primary => _keys[0];

    /// <inheritdoc />
    public int Count => _keys.Length;

    /// <inheritdoc />
    public CaltropKey this[int index] => _keys[index];

    /// <summary>
    /// Parses keys separated by commas, semicolons or whitespace, newest first, for example from a single
    /// environment variable. Each key may be in any format <see cref="CaltropKey.Parse(string)"/> accepts.
    /// </summary>
    /// <param name="text">The keys, newest first.</param>
    /// <exception cref="CaltropException">The text contains no keys or an invalid key.</exception>
    public static CaltropKeyRing Parse(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        string[] parts = text.Split([',', ';', ' ', '\t', '\r', '\n'], StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length == 0)
        {
            throw new CaltropException(CaltropErrorCode.InvalidKey, "The key ring text contains no keys.");
        }

        CaltropKey[] keys = Array.ConvertAll(parts, CaltropKey.Parse);
        return new CaltropKeyRing(keys[0], keys[1..]);
    }

    /// <inheritdoc />
    public IEnumerator<CaltropKey> GetEnumerator() => ((IEnumerable<CaltropKey>)_keys).GetEnumerator();

    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

    /// <summary>Lists the key ids. Never contains key material.</summary>
    public override string ToString() => $"CaltropKeyRing(primary {Primary.Id}, {Count} key(s))";
}
