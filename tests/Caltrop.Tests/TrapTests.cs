using System.Security.Cryptography;

namespace CaltropSecurity.Tests;

[Collection(GlobalState.Name)]
public sealed class TrapTests : IDisposable
{
    public TrapTests() => GlobalState.Reset();

    public void Dispose() => GlobalState.Reset();

    [Fact]
    public void Trigger_raises_a_custom_alarm()
    {
        using var alarms = new AlarmRecorder();

        Caltrop.Traps.Trigger("Fake admin page", "203.0.113.9");

        CaltropAlarm alarm = Assert.Single(alarms.Alarms);
        Assert.Equal(CaltropAlarmKind.Custom, alarm.Kind);
        Assert.Equal("Fake admin page", alarm.Trap);
        Assert.Equal("203.0.113.9", alarm.Subject);
        Assert.Contains("Fake admin page", alarm.Message);
        Assert.False(alarm.CausedLockDown);
        Assert.False(Caltrop.Traps.IsLockedDown);
    }

    [Fact]
    public void Alarms_change_nothing_by_default()
    {
        using var key = CaltropKey.Generate();

        Caltrop.Traps.Trigger("Test");

        Assert.False(Caltrop.Traps.IsLockedDown);
        Assert.Equal("still works", Caltrop.Decrypt(Caltrop.Encrypt("still works", key), key));
    }

    [Fact]
    public void LockDownOn_locks_down_only_for_the_chosen_kinds()
    {
        Caltrop.Traps.LockDownOn = CaltropAlarmKind.DecoyUsed;
        Caltrop.Traps.Trigger("Not a decoy");
        Assert.False(Caltrop.Traps.IsLockedDown);

        Caltrop.Traps.LockDownOn = CaltropAlarmKind.DecoyUsed | CaltropAlarmKind.Custom;
        Caltrop.Traps.Trigger("Now it counts");
        Assert.True(Caltrop.Traps.IsLockedDown);
        Assert.Equal("Now it counts", Caltrop.Traps.LockedDownBy!.Trap);
    }

    [Fact]
    public void Lockdown_wipes_keys_and_refuses_to_work()
    {
        var key = CaltropKey.Generate();
        var pair = CaltropKeyPair.Generate();
        string encrypted = Caltrop.Encrypt("secret", key);
        using var alarms = new AlarmRecorder();

        Caltrop.Traps.LockDown("Debugger attached");

        Assert.True(Caltrop.Traps.IsLockedDown);
        Assert.True(Assert.Single(alarms.Alarms).CausedLockDown);
        TestData.Throws(CaltropErrorCode.LockedDown, () => Caltrop.Decrypt(encrypted, key));
        TestData.Throws(CaltropErrorCode.LockedDown, () => Caltrop.Encrypt("more", key));
        TestData.Throws(CaltropErrorCode.LockedDown, () => key.Export());
        TestData.Throws(CaltropErrorCode.LockedDown, () => Caltrop.Sign("x", pair));
        TestData.Throws(CaltropErrorCode.LockedDown, () => Caltrop.Passwords.Hash("a password"));
        TestData.Throws(CaltropErrorCode.LockedDown, () => Caltrop.EncryptWithPassword("x", "a password"));
        TestData.Throws(CaltropErrorCode.LockedDown, () => Caltrop.Webhooks.Sign("body", "whsec_test"));
        TestData.Throws(CaltropErrorCode.LockedDown, () => Caltrop.Hashing.HmacSha256("m", "s"));
        TestData.Throws(CaltropErrorCode.LockedDown, () => CaltropKey.Generate().Export());
        CaltropException ex = TestData.Throws(CaltropErrorCode.LockedDown, () => Caltrop.UseKey(CaltropKey.Generate()));
        Assert.Contains("Debugger attached", ex.Message);
        Assert.Contains("Restart the app", ex.Message);
    }

    [Fact]
    public void Lockdown_zeroes_the_key_bytes_in_memory()
    {
        var key = CaltropKey.FromBytes(RandomNumberGenerator.GetBytes(32));
        byte[] material = (byte[])typeof(CaltropKey)
            .GetField("_material", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!
            .GetValue(key)!;
        Assert.NotEqual(new byte[32], material);

        Caltrop.Traps.LockDown("Test");

        Assert.Equal(new byte[32], material);
    }

    [Fact]
    public void Lockdown_wipes_the_default_keys_and_CALTROP_KEY_cannot_bring_them_back()
    {
        using var key = CaltropKey.Generate();
        Environment.SetEnvironmentVariable(Caltrop.KeyEnvironmentVariable, key.Export());
        Caltrop.UseKey(CaltropKey.Generate());

        Caltrop.Traps.LockDown("Test");

        TestData.Throws(CaltropErrorCode.LockedDown, () => Caltrop.Encrypt("x"));
        TestData.Throws(CaltropErrorCode.LockedDown, () => Caltrop.DefaultKeys);
        Assert.Null(Environment.GetEnvironmentVariable(Caltrop.KeyEnvironmentVariable));
    }

    [Fact]
    public void A_broken_alarm_handler_cannot_stop_a_trap()
    {
        EventHandler<CaltropAlarm> broken = (_, _) => throw new InvalidOperationException("handler bug");
        Caltrop.Traps.Alarm += broken;
        using var alarms = new AlarmRecorder();
        Caltrop.Traps.LockDownOn = CaltropAlarmKind.Custom;

        Caltrop.Traps.Trigger("Test");

        Assert.Single(alarms.Alarms);
        Assert.True(Caltrop.Traps.IsLockedDown);
    }

    [Fact]
    public void Alarms_are_written_to_the_log_before_a_lockdown()
    {
        using var folder = new TempFolder();
        var key = CaltropKey.Generate();
        using (var log = new CaltropLog(folder.File("alarms.log"), key))
        {
            Caltrop.Traps.Log = log;
            Caltrop.Traps.LockDownOn = CaltropAlarmKind.Custom;

            Caltrop.Traps.Trigger("Honeypot", "mallory");
        }

        string text = File.ReadAllText(folder.File("alarms.log"));
        Assert.Contains("Honeypot", text);
        Assert.Contains("mallory", text);
        Assert.Contains("locked itself down", text);
    }

    [Fact]
    public void Tampered_data_raises_a_tampering_alarm()
    {
        using var key = CaltropKey.Generate();
        byte[] encrypted = Caltrop.Encrypt([1, 2, 3], key);
        using var alarms = new AlarmRecorder();

        TestData.Throws(CaltropErrorCode.AuthenticationFailed, () => Caltrop.Decrypt(TestData.FlipBit(encrypted, encrypted.Length - 1), key));

        Assert.Equal(CaltropAlarmKind.Tampering, Assert.Single(alarms.Alarms).Kind);
    }

    [Fact]
    public void A_forged_token_and_a_changed_signature_raise_tampering_alarms()
    {
        using var key = CaltropKey.Generate();
        using var pair = CaltropKeyPair.Generate();
        string token = Caltrop.Tokens.Create("user:42", key, TimeSpan.FromHours(1));
        string signature = Caltrop.Sign("pay alice 10", pair);
        using var alarms = new AlarmRecorder();

        Assert.False(Caltrop.Tokens.TryValidate(token, key, out _, purpose: "different purpose"));
        Assert.False(Caltrop.VerifySignature("pay mallory 1000", signature, pair.PublicKey));

        Assert.Equal(2, alarms.Alarms.Count(a => a.Kind == CaltropAlarmKind.Tampering));
    }

    [Fact]
    public void A_wrong_password_is_not_reported_as_tampering()
    {
        string encrypted = Caltrop.EncryptWithPassword("x", "the right password");
        using var alarms = new AlarmRecorder();

        TestData.Throws(CaltropErrorCode.AuthenticationFailed, () => Caltrop.DecryptWithPassword(encrypted, "a wrong password"));

        Assert.Empty(alarms.Alarms);
    }

    [Fact]
    public void LockDownOn_rejects_unknown_kinds()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => Caltrop.Traps.LockDownOn = (CaltropAlarmKind)64);
    }
}
