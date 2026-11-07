using System.Net;
using System.Net.NetworkInformation;
using Lantern.Core.Devices;
using Xunit;

namespace Lantern.Core.Tests;

public sealed class DeviceRegistryTests
{
    [Fact]
    public void Remove_DeletesOnlyTheRequestedDeviceIdentity()
    {
        var registry = new DeviceRegistry();
        var firstIp = IPAddress.Parse("192.168.31.20");
        var secondIp = IPAddress.Parse("192.168.31.21");
        var firstMac = PhysicalAddress.Parse("AABBCCDDEE20");
        var secondMac = PhysicalAddress.Parse("AABBCCDDEE21");
        var now = DateTimeOffset.Parse("2026-11-06T12:00:00Z");

        registry.Observe(firstIp, firstMac, now, "Phone");
        registry.Observe(secondIp, secondMac, now, "Tablet");

        Assert.True(registry.Remove(firstMac));

        var remaining = Assert.Single(registry.Peek());
        Assert.Equal(secondMac, remaining.MacAddress);
        Assert.False(registry.Remove(firstMac));
    }

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

    [Fact]
    public void ObserveIpOnly_AddsLiveInventoryWithoutInventingAMacAddress()
    {
        var registry = new DeviceRegistry();
        var ip = IPAddress.Parse("192.168.31.45");
        var observedAt = DateTimeOffset.Parse("2026-11-06T12:30:00Z");

        registry.ObserveIpOnly(ip, observedAt, "Living-room speaker");

        var device = Assert.Single(registry.Peek());
        Assert.Equal(ip, device.IpAddress);
        Assert.Equal(PhysicalAddress.None, device.MacAddress);
        Assert.False(device.HasMacAddress);
        Assert.Equal(observedAt, device.LastSeen);
        Assert.Equal("Living-room speaker", device.HostName);
    }

    [Fact]
    public void Observe_WithVerifiedMac_ReplacesIpOnlyEntryAtThatAddress()
    {
        var registry = new DeviceRegistry();
        var ip = IPAddress.Parse("192.168.31.46");
        var mac = PhysicalAddress.Parse("AABBCCDDEE46");
        var observedAt = DateTimeOffset.Parse("2026-11-06T12:35:00Z");

        registry.ObserveIpOnly(ip, observedAt.AddSeconds(-5), "Unknown host");
        registry.Observe(ip, mac, observedAt, "Verified host");

        var device = Assert.Single(registry.Peek());
        Assert.Equal(ip, device.IpAddress);
        Assert.Equal(mac, device.MacAddress);
        Assert.True(device.HasMacAddress);
        Assert.Equal("Verified host", device.HostName);
    }

    [Fact]
    public void RemoveIpOnly_DeletesOnlyTheRequestedIpIdentity()
    {
        var registry = new DeviceRegistry();
        var first = IPAddress.Parse("192.168.31.47");
        var second = IPAddress.Parse("192.168.31.48");
        registry.ObserveIpOnly(first, DateTimeOffset.UtcNow);
        registry.ObserveIpOnly(second, DateTimeOffset.UtcNow);

        Assert.True(registry.RemoveIpOnly(first));

        var remaining = Assert.Single(registry.Peek());
        Assert.Equal(second, remaining.IpAddress);
        Assert.False(remaining.HasMacAddress);
    }
}
