namespace CaltropSecurity.Internal;

/// <summary>Something that holds secrets in memory and can wipe them.</summary>
internal interface IWipeable
{
    /// <summary>Zeroes every secret this object holds. Must be safe to call more than once and from any thread.</summary>
    void Wipe();
}

/// <summary>
/// Tracks every live object that holds secrets (keys, key pairs, open vaults, logs), so a lockdown can wipe them
/// all. Uses weak references, so tracking never keeps an object alive.
/// </summary>
internal static class Wipeables
{
    private static readonly Lock s_gate = new();
    private static readonly List<WeakReference<IWipeable>> s_items = [];
    private static int s_pruneAt = 64;

    public static void Register(IWipeable item)
    {
        lock (s_gate)
        {
            if (s_items.Count >= s_pruneAt)
            {
                s_items.RemoveAll(static reference => !reference.TryGetTarget(out _));
                s_pruneAt = Math.Max(64, s_items.Count * 2);
            }

            s_items.Add(new WeakReference<IWipeable>(item));
        }
    }

    public static void WipeAll()
    {
        List<IWipeable> alive = [];
        lock (s_gate)
        {
            foreach (WeakReference<IWipeable> reference in s_items)
            {
                if (reference.TryGetTarget(out IWipeable? item))
                {
                    alive.Add(item);
                }
            }

            s_items.Clear();
        }

        foreach (IWipeable item in alive)
        {
            item.Wipe();
        }
    }
}
