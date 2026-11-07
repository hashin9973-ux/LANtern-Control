namespace Lantern.App.Services;

public enum DevicePresence
{
    Online,
    Offline,
    Hidden,
}

public static class DevicePresencePolicy
{
    public static TimeSpan OfflineAfter { get; } = TimeSpan.FromSeconds(15);

    // Keep a last-known inventory entry visible for 30 days after its last
    // observation. Missing timestamps represent remembered, not live, devices.
    public static TimeSpan HideAfter { get; } = TimeSpan.FromDays(30);

    public static DevicePresence Classify(DateTimeOffset lastSeen, DateTimeOffset now)
    {
        if (lastSeen == DateTimeOffset.MinValue)
        {
            return DevicePresence.Offline;
        }

        var age = now - lastSeen;
        if (age <= OfflineAfter)
        {
            return DevicePresence.Online;
        }

        return age < HideAfter ? DevicePresence.Offline : DevicePresence.Hidden;
    }
}
