namespace CaltropSecurity.Internal;

/// <summary>Raises <see cref="CaltropAlarmKind.Tampering"/> alarms when data that was made with the right key fails its integrity check.</summary>
internal static class Tampering
{
    public static void Raise(string trap, string message, string? subject = null) =>
        Caltrop.Traps.Raise(CaltropAlarmKind.Tampering, trap, message, subject);
}
