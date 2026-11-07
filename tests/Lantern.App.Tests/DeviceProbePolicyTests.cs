using System.Net;
using System.Net.NetworkInformation;
using Lantern.App.Services;
using Lantern.Core.Devices;
using Lantern.Core.Networking;
using Xunit;

namespace Lantern.App.Tests;

public sealed class DeviceProbePolicyTests
{
    [Fact]
    public void GetTargets_OnlyReturnsStaleRememberedAddressesOnTheSelectedLan()
    {
        var now = DateTimeOffset.Parse("2026-11-06T12:00:00Z");
        var local = IPAddress.Parse("192.168.31.10");
        var gateway = IPAddress.Parse("192.168.31.1");
        var adapter = new AdapterProfile(
            "wifi",
            "Wi-Fi",
            "Test Wi-Fi",
            local,
            24,
            gateway,
            PhysicalAddress.Parse("001122334455"));
        var registry = new DeviceRegistry();
        registry.Remember(
            IPAddress.Parse("192.168.31.20"),
            PhysicalAddress.Parse("AABBCCDDEE20"),
            now.AddMinutes(-1),
            "Stale phone",
            now.AddMinutes(-1));
        registry.Remember(
            IPAddress.Parse("192.168.31.21"),
            PhysicalAddress.Parse("AABBCCDDEE21"),
            now,
            "Recently seen tablet",
            now.AddSeconds(-10));
        registry.Remember(
            IPAddress.Parse("192.168.31.22"),
            PhysicalAddress.Parse("AABBCCDDEE22"),
            DateTimeOffset.MinValue,
            "Legacy device");
        registry.Remember(
            gateway,
            PhysicalAddress.Parse("001122334401"),
            now.AddMinutes(-5),
            "Gateway",
            now.AddMinutes(-5));
        registry.Remember(
            local,
            adapter.LocalMac,
            now,
            "Controller",
            now);
        registry.Remember(
            IPAddress.Parse("192.168.32.23"),
            PhysicalAddress.Parse("AABBCCDDEE23"),
            now.AddMinutes(-5),
            "Other subnet",
            now.AddMinutes(-5));

        var targets = DeviceProbePolicy.GetTargets(
            registry.Peek(),
            adapter,
            now,
            force: false);

        Assert.Equal(
            new[]
            {
                IPAddress.Parse("192.168.31.20"),
                IPAddress.Parse("192.168.31.22"),
            },
            targets);
    }

    [Fact]
    public void GetTargets_RespectsCooldownEvenForManualForcedScans()
    {
        var now = DateTimeOffset.Parse("2026-11-06T12:00:00Z");
        var address = IPAddress.Parse("192.168.31.21");
        var adapter = new AdapterProfile(
            "wifi",
            "Wi-Fi",
            "Test Wi-Fi",
            IPAddress.Parse("192.168.31.10"),
            24,
            IPAddress.Parse("192.168.31.1"),
            PhysicalAddress.Parse("001122334455"));
        var registry = new DeviceRegistry();
        registry.Remember(
            address,
            PhysicalAddress.Parse("AABBCCDDEE21"),
            now,
            "Recently seen tablet",
            now);

        var lastProbeAt = new Dictionary<IPAddress, DateTimeOffset>
        {
            [address] = now.AddSeconds(-30),
        };

        Assert.Empty(DeviceProbePolicy.GetTargets(
            registry.Peek(),
            adapter,
            now,
            force: true,
            lastProbeAt));

        Assert.Equal(
            new[] { address },
            DeviceProbePolicy.GetTargets(
                registry.Peek(),
                adapter,
                now.AddSeconds(60),
                force: true,
                lastProbeAt));
    }

    [Fact]
    public void GetTargets_ForceChecksKnownRecentDevicesButNeverEnumeratesUnknownHosts()
    {
        var now = DateTimeOffset.Parse("2026-11-06T12:00:00Z");
        var adapter = new AdapterProfile(
            "wifi",
            "Wi-Fi",
            "Test Wi-Fi",
            IPAddress.Parse("192.168.31.10"),
            24,
            IPAddress.Parse("192.168.31.1"),
            PhysicalAddress.Parse("001122334455"));
        var registry = new DeviceRegistry();
        registry.Remember(
            IPAddress.Parse("192.168.31.21"),
            PhysicalAddress.Parse("AABBCCDDEE21"),
            now,
            "Recently seen tablet",
            now.AddSeconds(-10));

        var targets = DeviceProbePolicy.GetTargets(
            registry.Peek(),
            adapter,
            now,
            force: true);

        Assert.Equal(new[] { IPAddress.Parse("192.168.31.21") }, targets);
    }
}
