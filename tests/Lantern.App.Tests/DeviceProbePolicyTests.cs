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
    public void GetTargets_StopsAtTheMaximumBatchSize()
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
        for (var host = 11; host <= 160; host++)
        {
            registry.Remember(
                IPAddress.Parse($"192.168.31.{host}"),
                PhysicalAddress.Parse($"AABBCCDD{host / 256:X2}{host % 256:X2}"),
                now,
                $"Device {host}");
        }

        var targets = DeviceProbePolicy.GetTargets(
            registry.Peek(),
            adapter,
            now,
            force: true);

        Assert.Equal(DeviceProbePolicy.MaxTargetsPerBatch, targets.Count);
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
            lastProbeAt: lastProbeAt));

        Assert.Equal(
            new[] { address },
            DeviceProbePolicy.GetTargets(
                registry.Peek(),
                adapter,
                now.AddSeconds(60),
                force: true,
                lastProbeAt: lastProbeAt));
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

    [Fact]
    public void GetDiscoveryTargets_EnumeratesLocalSegmentAndExcludesControllerAndGateway()
    {
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

        var targets = DeviceProbePolicy.GetDiscoveryTargets(adapter);

        Assert.Equal(252, targets.Count);
        Assert.DoesNotContain(local, targets);
        Assert.DoesNotContain(gateway, targets);
        Assert.Contains(IPAddress.Parse("192.168.31.20"), targets);
        Assert.Equal(targets.Count, targets.Distinct().Count());
    }

    [Fact]
    public void GetDiscoveryTargets_LimitsLargeNetworksToTheControllerLocal24()
    {
        var local = IPAddress.Parse("10.20.30.40");
        var gateway = IPAddress.Parse("10.20.30.1");
        var adapter = new AdapterProfile(
            "ethernet",
            "Ethernet",
            "Test Ethernet",
            local,
            16,
            gateway,
            PhysicalAddress.Parse("001122334466"));

        var targets = DeviceProbePolicy.GetDiscoveryTargets(adapter);

        Assert.Equal(252, targets.Count);
        Assert.All(targets, address => Assert.StartsWith("10.20.30.", address.ToString()));
        Assert.DoesNotContain(local, targets);
        Assert.DoesNotContain(gateway, targets);
    }

    [Fact]
    public void GetDiscoveryTargets_RespectsTheMaximumTargetLimit()
    {
        var adapter = new AdapterProfile(
            "wifi",
            "Wi-Fi",
            "Test Wi-Fi",
            IPAddress.Parse("192.168.31.10"),
            24,
            IPAddress.Parse("192.168.31.1"),
            PhysicalAddress.Parse("001122334455"));

        var targets = DeviceProbePolicy.GetDiscoveryTargets(adapter);

        Assert.True(targets.Count <= DeviceProbePolicy.MaxDiscoveryTargetsPerScan);
        Assert.Equal(252, targets.Count);
    }

    [Fact]
    public void DiscoveryRetrySpacing_IsPaced()
    {
        Assert.Equal(TimeSpan.FromMilliseconds(150), DeviceProbePolicy.DiscoveryRetrySpacing);
    }

}
