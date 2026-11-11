namespace CaltropSecurity.Internal;

internal static class KeyList
{
    /// <summary>Validates a caller-supplied key collection and returns it as a list.</summary>
    public static IReadOnlyList<CaltropKey> From(IEnumerable<CaltropKey> keys, string parameterName)
    {
        ArgumentNullException.ThrowIfNull(keys, parameterName);
        IReadOnlyList<CaltropKey> list = keys as IReadOnlyList<CaltropKey> ?? [.. keys];
        if (list.Count == 0)
        {
            throw new ArgumentException("At least one key is required.", parameterName);
        }

        for (int i = 0; i < list.Count; i++)
        {
            if (list[i] is null)
            {
                throw new ArgumentException("The key collection contains a null key.", parameterName);
            }
        }

        return list;
    }

    public static IReadOnlyList<CaltropKey> Single(CaltropKey key, string parameterName)
    {
        ArgumentNullException.ThrowIfNull(key, parameterName);
        return [key];
    }
}
