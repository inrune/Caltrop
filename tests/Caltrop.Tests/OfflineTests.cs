namespace CaltropSecurity.Tests;

// Caltrop must work fully offline. These tests fail if the library ever references the parts of .NET that
// reach the network (HTTP, sockets, DNS, TLS, web requests) or start other programs that could.
public class OfflineTests
{
    [Fact]
    public void Caltrop_never_uses_the_network()
    {
        string[] references = ReferencedAssemblies();

        Assert.NotEmpty(references);
        Assert.Empty(references.Where(name => name.StartsWith("System.Net", StringComparison.Ordinal)));
    }

    [Fact]
    public void Caltrop_never_starts_other_programs()
    {
        Assert.Empty(ReferencedAssemblies().Where(name => name == "System.Diagnostics.Process"));
    }

    private static string[] ReferencedAssemblies() =>
        [.. typeof(Caltrop).Assembly.GetReferencedAssemblies().Select(reference => reference.Name ?? "")];
}
