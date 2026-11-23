using CaltropSecurity.Internal;

namespace CaltropSecurity.Tests;

[Collection(GlobalState.Name)]
public sealed class TamperTests : IDisposable
{
    private readonly CaltropKey _key = CaltropKey.Generate();
    private readonly TempFolder _folder = new();

    public TamperTests() => GlobalState.Reset();

    public void Dispose()
    {
        _folder.Dispose();
        GlobalState.Reset();
    }

    [Fact]
    public void Unchanged_data_passes_and_changed_data_fails_with_an_alarm()
    {
        string seal = Caltrop.Tamper.Seal("price=10", _key);
        Assert.StartsWith("cts_", seal);
        using var alarms = new AlarmRecorder();

        Assert.True(Caltrop.Tamper.Check("price=10", seal, _key));
        Assert.Empty(alarms.Alarms);
        Assert.False(Caltrop.Tamper.Check("price=1", seal, _key));

        Assert.Equal(CaltropAlarmKind.Tampering, Assert.Single(alarms.Alarms).Kind);
    }

    [Fact]
    public void A_damaged_or_foreign_seal_fails()
    {
        string seal = Caltrop.Tamper.Seal([1, 2, 3], _key);
        char last = seal[^1];
        string damaged = seal[..^1] + (last == 'A' ? 'B' : 'A');

        Assert.False(Caltrop.Tamper.Check([1, 2, 3], damaged, _key));
        Assert.False(Caltrop.Tamper.Check([1, 2, 3], null, _key));
        Assert.False(Caltrop.Tamper.Check([1, 2, 3], "not a seal", _key));
        using var other = CaltropKey.Generate();
        Assert.False(Caltrop.Tamper.Check([1, 2, 3], seal, other));
    }

    [Fact]
    public void Files_are_sealed_and_checked()
    {
        string path = _folder.File("settings.json");
        File.WriteAllText(path, """{ "admin": false }""");
        string seal = Caltrop.Tamper.SealFile(path, _key);

        Assert.True(Caltrop.Tamper.CheckFile(path, seal, _key));

        File.WriteAllText(path, """{ "admin": true  }""");
        using var alarms = new AlarmRecorder();
        Assert.False(Caltrop.Tamper.CheckFile(path, seal, _key));
        Assert.Equal(path, Assert.Single(alarms.Alarms).Subject);

        File.Delete(path);
        Assert.False(Caltrop.Tamper.CheckFile(path, seal, _key));
    }

    [Fact]
    public void A_file_seal_and_a_data_seal_of_the_same_bytes_agree()
    {
        string path = _folder.File("data.bin");
        byte[] data = TestData.RandomBytes(100_000);
        File.WriteAllBytes(path, data);

        Assert.True(Caltrop.Tamper.Check(data, Caltrop.Tamper.SealFile(path, _key), _key));
    }

    [Theory]
    [InlineData("add")]
    [InlineData("remove")]
    [InlineData("rename")]
    [InlineData("change")]
    [InlineData("hidden")]
    public void Any_change_to_a_folder_breaks_its_seal(string change)
    {
        string plugins = Path.Combine(_folder.Path, "plugins");
        Directory.CreateDirectory(Path.Combine(plugins, "sub"));
        File.WriteAllText(Path.Combine(plugins, "a.dll"), "A");
        File.WriteAllText(Path.Combine(plugins, "sub", "b.dll"), "B");
        string seal = Caltrop.Tamper.SealFolder(plugins, _key);
        Assert.True(Caltrop.Tamper.CheckFolder(plugins, seal, _key));

        switch (change)
        {
            case "add": File.WriteAllText(Path.Combine(plugins, "evil.dll"), "X"); break;
            case "remove": File.Delete(Path.Combine(plugins, "a.dll")); break;
            case "rename": File.Move(Path.Combine(plugins, "a.dll"), Path.Combine(plugins, "c.dll")); break;
            case "change": File.WriteAllText(Path.Combine(plugins, "sub", "b.dll"), "b"); break;
            case "hidden":
                string hidden = Path.Combine(plugins, ".hidden");
                File.WriteAllText(hidden, "X");
                File.SetAttributes(hidden, FileAttributes.Hidden);
                break;
        }

        Assert.False(Caltrop.Tamper.CheckFolder(plugins, seal, _key));
    }

    [Fact]
    public void A_folder_seal_cannot_be_used_as_a_file_seal()
    {
        string folderSeal = Caltrop.Tamper.SealFolder(_folder.Path, _key);
        string path = _folder.File("x.txt");
        File.WriteAllText(path, "x");

        Assert.False(Caltrop.Tamper.CheckFile(path, folderSeal, _key));
    }

    [Fact]
    public void Seals_use_the_default_keys_when_no_key_is_given()
    {
        Caltrop.UseKey(_key);

        string seal = Caltrop.Tamper.Seal("hello");

        Assert.True(Caltrop.Tamper.Check("hello", seal));
        Assert.True(Caltrop.Tamper.Check("hello", seal, _key));
    }

    [Fact]
    public void The_built_Caltrop_dll_is_intact()
    {
        Assert.Equal(CaltropIntegrity.Intact, Caltrop.Tamper.CheckCaltrop());
    }

    [Fact]
    public void Changing_any_part_of_Caltrop_dll_is_detected()
    {
        byte[] file = File.ReadAllBytes(typeof(Caltrop).Assembly.Location);
        int slot = SelfSeal.FindSlot(file);
        Assert.True(slot > 0);
        byte[] expected = file.AsSpan(slot, SelfSeal.HashSize).ToArray();
        Assert.Equal(CaltropIntegrity.Intact, SelfSeal.Verify(file, expected));

        foreach (int index in new[] { 0x80, file.Length / 3, file.Length / 2, file.Length - 1 })
        {
            if (index >= slot && index < slot + SelfSeal.HashSize)
            {
                continue;
            }

            Assert.Equal(CaltropIntegrity.Changed, SelfSeal.Verify(TestData.FlipBit(file, index), expected));
        }

        byte[] unsealed = (byte[])file.Clone();
        Array.Clear(unsealed, slot, SelfSeal.HashSize);
        Assert.Equal(CaltropIntegrity.Changed, SelfSeal.Verify(unsealed, new byte[SelfSeal.HashSize]));
    }

    [Fact]
    public void Signing_Caltrop_dll_later_does_not_break_its_seal()
    {
        byte[] file = File.ReadAllBytes(typeof(Caltrop).Assembly.Location);
        int slot = SelfSeal.FindSlot(file);
        byte[] expected = file.AsSpan(slot, SelfSeal.HashSize).ToArray();

        // Simulate Authenticode signing: append a certificate, point the certificate table at it, update the checksum.
        int pe = BitConverter.ToInt32(file, 0x3C);
        int optional = pe + 24;
        bool plus = BitConverter.ToUInt16(file, optional) == 0x20B;
        int entry = optional + (plus ? 112 : 96) + 32;
        byte[] signed = [.. file, .. TestData.RandomBytes(1024)];
        BitConverter.GetBytes(file.Length).CopyTo(signed, entry);
        BitConverter.GetBytes(1024).CopyTo(signed, entry + 4);
        BitConverter.GetBytes(0x12345678).CopyTo(signed, optional + 64);

        Assert.Equal(CaltropIntegrity.Intact, SelfSeal.Verify(signed, expected));
    }
}
