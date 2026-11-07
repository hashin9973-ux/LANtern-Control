using Lantern.App.Services;
using Xunit;

namespace Lantern.App.Tests;

public sealed class DevicePresencePolicyTests
{
    [Theory]
    [InlineData(0, DevicePresence.Online)]
    [InlineData(15, DevicePresence.Online)]
    [InlineData(16, DevicePresence.Offline)]
    [InlineData(44, DevicePresence.Offline)]
    [InlineData(45, DevicePresence.Offline)]
    [InlineData(2592000, DevicePresence.Hidden)]
    public void Classify_UsesMissedLivenessWindows(int ageSeconds, DevicePresence expected)
    {
        var now = DateTimeOffset.Parse("2026-08-01T12:00:00Z");

        var presence = DevicePresencePolicy.Classify(
            now.AddSeconds(-ageSeconds),
            now);

        Assert.Equal(expected, presence);
    }

    [Fact]
    public void Classify_TreatsRememberedDevicesWithoutTimestampsAsOffline()
    {
        var now = DateTimeOffset.Parse("2026-08-01T12:00:00Z");

        Assert.Equal(
            DevicePresence.Offline,
            DevicePresencePolicy.Classify(DateTimeOffset.MinValue, now));
    }
}
