using System.Net;
using System.Net.NetworkInformation;
using Lantern.Core.Devices;
using Xunit;

namespace Lantern.Core.Tests;

public sealed class DeviceRegistryTests
{
    [Fact]
    public void Remember_RestoresLastSeenTimestampWithoutMarkingDeviceOnline()
    {
        var registry = new DeviceRegistry();
        var firstSeen = DateTimeOffset.Parse("2026-10-01T09:00:00Z");
        var lastSeen = DateTimeOffset.Parse("2026-11-05T14:30:00Z");
        var ip = IPAddress.Parse("192.168.31.20");
        var mac = PhysicalAddress.Parse("AABBCCDDEEFF");

        registry.Remember(ip, mac, firstSeen, "Tablet", lastSeen);

        var device = Assert.Single(registry.Peek());
        Assert.Equal(lastSeen, device.LastSeen);
        Assert.Equal(ip, device.IpAddress);
        Assert.Equal("Tablet", device.HostName);
    }

    [Fact]
    public void Remember_CacheRefreshDoesNotOverwriteARealLastSeenTimestamp()
    {
        var registry = new DeviceRegistry();
        var firstSeen = DateTimeOffset.Parse("2026-10-01T09:00:00Z");
        var lastSeen = DateTimeOffset.Parse("2026-11-05T14:30:00Z");
        var ip = IPAddress.Parse("192.168.31.20");
        var mac = PhysicalAddress.Parse("AABBCCDDEEFF");

        registry.Remember(ip, mac, firstSeen, "Tablet", lastSeen);
        registry.Remember(ip, mac, DateTimeOffset.MinValue, "Tablet");

        var device = Assert.Single(registry.Peek());
        Assert.Equal(lastSeen, device.LastSeen);
    }
}
