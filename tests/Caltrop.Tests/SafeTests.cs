namespace CaltropSecurity.Tests;

public sealed class SafeTests : IDisposable
{
    private readonly TempFolder _folder = new();

    public void Dispose() => _folder.Dispose();

    [Theory]
    [InlineData("photo.jpg")]
    [InlineData("albums/2026/photo.jpg")]
    [InlineData("albums/../photo.jpg")]
    [InlineData("not-there-yet/new.txt")]
    public void PathInside_allows_paths_that_stay_inside(string path)
    {
        string full = Caltrop.Safe.PathInside(_folder.Path, path);

        Assert.StartsWith(Path.GetFullPath(_folder.Path), full);
    }

    [Theory]
    [InlineData("../secret.txt")]
    [InlineData("albums/../../secret.txt")]
    [InlineData("/etc/passwd")]
    [InlineData("\\windows\\system32")]
    [InlineData("C:\\Windows\\win.ini")]
    [InlineData("C:secret.txt")]
    [InlineData("\\\\server\\share\\file")]
    [InlineData("..")]
    [InlineData(".")]
    [InlineData("")]
    [InlineData("file\0.txt")]
    [InlineData("CON")]
    [InlineData("albums/nul.txt")]
    public void PathInside_blocks_paths_that_escape(string path)
    {
        TestData.Throws(CaltropErrorCode.UnsafeInput, () => Caltrop.Safe.PathInside(_folder.Path, path));
    }

    [Fact]
    public void PathInside_blocks_links_that_point_outside()
    {
        using var outside = new TempFolder();
        File.WriteAllText(outside.File("secret.txt"), "secret");
        try
        {
            Directory.CreateSymbolicLink(Path.Combine(_folder.Path, "shortcut"), outside.Path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or PlatformNotSupportedException)
        {
            Assert.Skip("This machine does not allow creating symbolic links.");
        }

        TestData.Throws(CaltropErrorCode.UnsafeInput, () => Caltrop.Safe.PathInside(_folder.Path, "shortcut/secret.txt"));
    }

    [Theory]
    [InlineData("invoice.pdf", "invoice.pdf")]
    [InlineData("../../etc/passwd", "passwd")]
    [InlineData("C:\\Users\\me\\evil.exe", "evil.exe")]
    [InlineData(".htaccess", "htaccess")]
    [InlineData("CON", "_CON")]
    [InlineData("con.txt", "_con.txt")]
    [InlineData("what?.txt", "what_.txt")]
    [InlineData("photo\u202Egpj.exe", "photogpj.exe")]
    [InlineData("  spaced.txt.  ", "spaced.txt")]
    [InlineData("", "file")]
    [InlineData("...", "file")]
    public void FileName_makes_names_safe(string input, string expected)
    {
        Assert.Equal(expected, Caltrop.Safe.FileName(input));
    }

    [Fact]
    public void FileName_keeps_the_extension_when_it_shortens_a_name()
    {
        string name = Caltrop.Safe.FileName(new string('a', 500) + ".pdf");

        Assert.Equal(200, name.Length);
        Assert.EndsWith(".pdf", name);
    }

    [Fact]
    public void Html_encodes_everything_that_could_become_markup()
    {
        Assert.Equal(
            "&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt; &amp; &quot;quoted&quot; &#96;tick&#96;",
            Caltrop.Safe.Html("<script>alert('x')</script> & \"quoted\" `tick`"));
        Assert.Equal(string.Empty, Caltrop.Safe.Html(null));
        Assert.Equal("café 😀", Caltrop.Safe.Html("café 😀"));
    }

    [Fact]
    public void Mask_hides_card_numbers_but_not_other_numbers()
    {
        Assert.Equal("card **** **** **** 1111 ok", Caltrop.Safe.Mask("card 4111 1111 1111 1111 ok"));
        Assert.Equal("card ************0004", Caltrop.Safe.Mask("card 5500000000000004"));
        Assert.Equal("order 1234567890123 shipped", Caltrop.Safe.Mask("order 1234567890123 shipped"));
    }

    [Fact]
    public void Mask_hides_emails_secrets_and_tokens()
    {
        using var key = CaltropKey.Generate();
        string apiKey = Caltrop.ApiKeys.Generate("acme_live");

        Assert.Equal("contact a***@example.com", Caltrop.Safe.Mask("contact alice.smith@example.com"));
        Assert.Equal("Server=db;Password=****;User=sa", Caltrop.Safe.Mask("Server=db;Password=hunter2;User=sa"));
        Assert.Equal("{\"api_key\": ****}", Caltrop.Safe.Mask("{\"api_key\": \"abc123\"}"));
        Assert.Equal("Authorization: Bearer ****", Caltrop.Safe.Mask("Authorization: Bearer abcdefghijklmnop"));
        Assert.Equal("token eyJ****", Caltrop.Safe.Mask("token eyJhbGciOi.eyJzdWIiOiIx.SflKxwRJSMeKKF2QT4fw"));
        Assert.Equal("key ctk_****", Caltrop.Safe.Mask("key " + key.Export()));
        Assert.Equal("key acme_live_****", Caltrop.Safe.Mask("key " + apiKey));
        Assert.Equal(string.Empty, Caltrop.Safe.Mask(null));
    }

    [Fact]
    public void CleanText_removes_invisible_and_direction_changing_characters()
    {
        Assert.Equal("admin", Caltrop.Safe.CleanText("ad\u200Bmin"));
        Assert.Equal("photo_gpj.exe", Caltrop.Safe.CleanText("photo_\u202Egpj.exe"));
        Assert.Equal("line one\nline two", Caltrop.Safe.CleanText("line one\nline two\u0007"));
        Assert.Equal("é", Caltrop.Safe.CleanText("e\u0301"));
        Assert.Equal("\uFFFD", Caltrop.Safe.CleanText("\uD800"));
    }

    [Theory]
    [InlineData("https://example.com/page", true)]
    [InlineData("http://example.com", true)]
    [InlineData("mailto:someone@example.com", true)]
    [InlineData("/relative/page?x=1", true)]
    [InlineData("page.html#top", true)]
    [InlineData("javascript:alert(1)", false)]
    [InlineData("  JaVaScRiPt:alert(1)", false)]
    [InlineData("java\tscript:alert(1)", false)]
    [InlineData("data:text/html,<script>alert(1)</script>", false)]
    [InlineData("vbscript:msgbox(1)", false)]
    [InlineData("javascript&#58;alert(1)", false)]
    [InlineData("", false)]
    public void IsSafeLink_allows_only_web_mail_and_relative_links(string url, bool expected)
    {
        Assert.Equal(expected, Caltrop.Safe.IsSafeLink(url));
    }
}
