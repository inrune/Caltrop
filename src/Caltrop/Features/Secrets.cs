using CaltropSecurity.Internal;

public static partial class Caltrop
{
    /// <summary>
    /// Keep secrets (passwords, API keys, connection strings) safely, with nothing to set up. They are stored
    /// encrypted in <c>secrets.vault</c> in <see cref="Folder"/>, locked with Caltrop's key.
    /// </summary>
    /// <example>
    /// <code>
    /// Caltrop.Secrets.Set("db-password", "hunter2");
    /// string? password = Caltrop.Secrets.Get("db-password");
    /// </code>
    /// </example>
    /// <remarks>Every change is saved straight away. For a vault of your own, in a file you choose or locked with a password, use <see cref="CaltropVault"/>.</remarks>
    public static class Secrets
    {
        /// <summary>The names of the stored secrets, sorted.</summary>
        public static IReadOnlyList<string> Names => Home.Secrets().Names;

        /// <summary>Stores a secret, replacing any with the same name.</summary>
        /// <param name="name">The secret's name, 1 to 256 characters. Names are case-sensitive.</param>
        /// <param name="value">The secret.</param>
        public static void Set(string name, string value) => Home.Secrets().Set(name, value);

        /// <summary>Stores a secret as bytes, replacing any with the same name.</summary>
        /// <param name="name">The secret's name, 1 to 256 characters. Names are case-sensitive.</param>
        /// <param name="value">The secret.</param>
        public static void Set(string name, byte[] value) => Home.Secrets().Set(name, value);

        /// <summary>Reads a secret.</summary>
        /// <param name="name">The secret's name.</param>
        /// <returns>The secret, or <see langword="null"/> if there is none with this name.</returns>
        public static string? Get(string name) => Home.Secrets().Get(name);

        /// <summary>Reads a secret as bytes.</summary>
        /// <param name="name">The secret's name.</param>
        /// <returns>A copy of the secret, or <see langword="null"/> if there is none with this name.</returns>
        public static byte[]? GetBytes(string name) => Home.Secrets().GetBytes(name);

        /// <summary><see langword="true"/> if there is a secret with this name.</summary>
        /// <param name="name">The secret's name.</param>
        public static bool Contains(string name) => Home.Secrets().Contains(name);

        /// <summary>Deletes a secret.</summary>
        /// <param name="name">The secret's name.</param>
        /// <returns><see langword="true"/> if it existed.</returns>
        public static bool Remove(string name) => Home.Secrets().Remove(name);
    }
}
