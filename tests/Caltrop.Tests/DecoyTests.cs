namespace CaltropSecurity.Tests;

[Collection(GlobalState.Name)]
public sealed class DecoyTests : IDisposable
{
    private readonly CaltropKey _key = CaltropKey.Generate();

    public DecoyTests()
    {
        GlobalState.Reset();
        Caltrop.UseKey(_key);
    }

    public void Dispose() => GlobalState.Reset();

    [Fact]
    public void A_decoy_password_hash_looks_real_and_never_matches()
    {
        string decoy = Caltrop.Decoys.PasswordHash();
        string real = Caltrop.Passwords.Hash("correct horse battery staple");

        Assert.Matches(@"^\$pbkdf2-sha256\$i=600000\$[A-Za-z0-9+/]{22}\$[A-Za-z0-9+/]{43}$", decoy);
        Assert.Equal(real.Length, decoy.Length);
        Assert.False(Caltrop.Passwords.NeedsRehash(decoy));

        using var alarms = new AlarmRecorder();
        Assert.False(Caltrop.Passwords.Verify("admin", decoy));
        Assert.True(Caltrop.Passwords.Verify("correct horse battery staple", real));

        CaltropAlarm alarm = Assert.Single(alarms.Alarms);
        Assert.Equal(CaltropAlarmKind.DecoyUsed, alarm.Kind);
        Assert.Equal("Decoy password", alarm.Trap);
    }

    [Fact]
    public void A_decoy_api_key_looks_real_but_is_refused_everywhere()
    {
        string decoy = Caltrop.Decoys.ApiKey("acme_live");
        string real = Caltrop.ApiKeys.Generate("acme_live");
        Assert.Equal(real.Length, decoy.Length);
        Assert.StartsWith("acme_live_", decoy);
        Assert.Matches("^acme_live_[A-Za-z0-9]{38}$", decoy);

        using var alarms = new AlarmRecorder();
        Assert.False(Caltrop.ApiKeys.IsWellFormed(decoy, "acme_live"));
        Assert.False(Caltrop.ApiKeys.Verify(decoy, Caltrop.ApiKeys.Hash(real)));
        Assert.True(Caltrop.ApiKeys.IsWellFormed(real, "acme_live"));

        Assert.True(alarms.Alarms.Count >= 2);
        Assert.All(alarms.Alarms, alarm => Assert.Equal(CaltropAlarmKind.DecoyUsed, alarm.Kind));
        Assert.Equal(decoy, alarms.Alarms[0].Subject);
    }

    [Fact]
    public void A_decoy_encrypted_value_decrypts_to_its_fake_content_and_trips_the_alarm()
    {
        string decoy = Caltrop.Decoys.Encrypted("4111 1111 1111 1111");
        string real = Caltrop.Encrypt("5500 0000 0000 0004");
        Assert.Equal(real.Length, decoy.Length);

        using var alarms = new AlarmRecorder();
        Assert.Equal("5500 0000 0000 0004", Caltrop.Decrypt(real));
        Assert.Empty(alarms.Alarms);

        Assert.Equal("4111 1111 1111 1111", Caltrop.Decrypt(decoy));
        Assert.Equal("Decoy data", Assert.Single(alarms.Alarms).Trap);
    }

    [Fact]
    public void A_decoy_can_lock_Caltrop_down()
    {
        string decoy = Caltrop.Decoys.Encrypted("bait");
        Caltrop.Traps.LockDownOn = CaltropAlarmKind.DecoyUsed;

        TestData.Throws(CaltropErrorCode.LockedDown, () => Caltrop.Decrypt(decoy));

        Assert.True(Caltrop.Traps.IsLockedDown);
        TestData.Throws(CaltropErrorCode.LockedDown, () => Caltrop.Encrypt("anything"));
    }

    [Fact]
    public void Decoys_with_a_context_need_the_same_context()
    {
        string decoy = Caltrop.Decoys.Encrypted("bait", _key, context: "user:7");
        using var alarms = new AlarmRecorder();

        Assert.Equal("bait", Caltrop.Decrypt(decoy, _key, context: "user:7"));
        Assert.Contains(alarms.Alarms, alarm => alarm.Kind == CaltropAlarmKind.DecoyUsed);
    }

    [Fact]
    public void Watched_values_and_all_decoy_kinds_are_recognized_by_Check()
    {
        Caltrop.Decoys.Watch("ceo-backup@example.com", "fake CEO email");
        using var alarms = new AlarmRecorder();

        Assert.True(Caltrop.Decoys.Check("ceo-backup@example.com"));
        Assert.True(Caltrop.Decoys.Check(Caltrop.Decoys.PasswordHash()));
        Assert.True(Caltrop.Decoys.Check(Caltrop.Decoys.ApiKey("acme")));
        Assert.True(Caltrop.Decoys.Check(Caltrop.Decoys.Encrypted("bait")));

        Assert.False(Caltrop.Decoys.Check("someone@example.com"));
        Assert.False(Caltrop.Decoys.Check(Caltrop.Passwords.Hash("a real password")));
        Assert.False(Caltrop.Decoys.Check(Caltrop.ApiKeys.Generate("acme")));
        Assert.False(Caltrop.Decoys.Check(Caltrop.Encrypt("real")));
        Assert.False(Caltrop.Decoys.Check(null));

        Assert.Equal(4, alarms.Alarms.Count);
        Assert.Equal("fake CEO email", alarms.Alarms[0].Subject);
    }

    [Fact]
    public void Real_values_never_look_like_decoys()
    {
        using var alarms = new AlarmRecorder();
        for (int i = 0; i < 200; i++)
        {
            Assert.False(Caltrop.Decoys.Check(Caltrop.ApiKeys.Generate("acme")));
            Assert.False(Caltrop.Decoys.Check(Caltrop.Encrypt("x")));
        }

        Assert.Empty(alarms.Alarms);
    }

    [Fact]
    public void Decoys_made_with_another_key_are_not_recognized()
    {
        string otherApps = Caltrop.Decoys.ApiKey("acme");
        Caltrop.UseKey(CaltropKey.Generate());
        using var alarms = new AlarmRecorder();

        Assert.True(Caltrop.ApiKeys.IsWellFormed(otherApps));
        Assert.Empty(alarms.Alarms);
    }

    [Fact]
    public void Making_a_decoy_needs_a_key()
    {
        GlobalState.Reset();
        Caltrop.Folder = null;

        Assert.Throws<InvalidOperationException>(() => Caltrop.Decoys.PasswordHash());
        Assert.Throws<InvalidOperationException>(() => Caltrop.Decoys.ApiKey("acme"));
    }

    [Fact]
    public void A_decoy_login_takes_as_long_as_a_real_one()
    {
        string decoy = Caltrop.Decoys.PasswordHash();
        string real = Caltrop.Passwords.Hash("a real password");
        Caltrop.Passwords.Verify("warm-up", real);

        var clock = System.Diagnostics.Stopwatch.StartNew();
        Caltrop.Passwords.Verify("guess", real);
        TimeSpan realTime = clock.Elapsed;
        clock.Restart();
        Caltrop.Passwords.Verify("guess", decoy);
        TimeSpan decoyTime = clock.Elapsed;

        Assert.True(decoyTime > realTime / 3, $"decoy {decoyTime.TotalMilliseconds} ms vs real {realTime.TotalMilliseconds} ms");
    }
}
