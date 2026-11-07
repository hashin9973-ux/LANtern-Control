using System.Net;
using System.Net.NetworkInformation;
using Lantern.App.Services;
using Lantern.Core.Networking;
using Xunit;

namespace Lantern.App.Tests;

public sealed class ArpIdentityMonitorTests
{
    private static readonly IPAddress ControllerIp = IPAddress.Parse("192.168.31.10");
    private static readonly PhysicalAddress ControllerMac = PhysicalAddress.Parse("001122334455");

    [Fact]
    public void Observe_ReportsTwoMacsClaimingOneAddress()
    {
        var monitor = new ArpIdentityMonitor();
        var ip = IPAddress.Parse("192.168.31.20");
        var firstMac = PhysicalAddress.Parse("AABBCCDDEEFF");
        var secondMac = PhysicalAddress.Parse("AABBCCDDEE01");
        var now = DateTimeOffset.Parse("2026-11-06T12:00:00Z");

        var first = monitor.Observe(Frame(ip, firstMac), ControllerIp, ControllerMac, now);
        var conflict = monitor.Observe(
            Frame(ip, secondMac),
            ControllerIp,
            ControllerMac,
            now.AddSeconds(5));

        Assert.False(first.IsConflict);
        Assert.True(conflict.IsConflict);
        Assert.Contains("Potential ARP identity conflict", conflict.Warning);
    }

    [Fact]
    public void Observe_ReportsOneMacClaimingMultipleAddresses()
    {
        var monitor = new ArpIdentityMonitor();
        var mac = PhysicalAddress.Parse("AABBCCDDEEFF");
        var now = DateTimeOffset.Parse("2026-11-06T12:00:00Z");

        _ = monitor.Observe(
            Frame(IPAddress.Parse("192.168.31.20"), mac),
            ControllerIp,
            ControllerMac,
            now);
        var conflict = monitor.Observe(
            Frame(IPAddress.Parse("192.168.31.21"), mac),
            ControllerIp,
            ControllerMac,
            now.AddSeconds(5));

        Assert.True(conflict.IsConflict);
        Assert.Contains("claiming both", conflict.Warning);
    }

    [Fact]
    public void Observe_ReportsEthernetAndArpSenderMismatch()
    {
        var monitor = new ArpIdentityMonitor();
        var senderMac = PhysicalAddress.Parse("AABBCCDDEEFF");
        var frame = new ArpFrameInfo(
            ArpOperation.Reply,
            PhysicalAddress.Parse("AABBCCDDEE01"),
            senderMac,
            IPAddress.Parse("192.168.31.20"),
            ControllerMac,
            ControllerIp);

        var observation = monitor.Observe(
            frame,
            ControllerIp,
            ControllerMac,
            DateTimeOffset.Parse("2026-11-06T12:00:00Z"));

        Assert.True(observation.IsConflict);
        Assert.Contains("differs from the ARP sender MAC", observation.Warning);
    }

    [Fact]
    public void Observe_ReportsTheControllerMacClaimedAtAnotherAddress()
    {
        var monitor = new ArpIdentityMonitor();
        var observation = monitor.Observe(
            Frame(IPAddress.Parse("192.168.31.20"), ControllerMac),
            ControllerIp,
            ControllerMac,
            DateTimeOffset.Parse("2026-11-06T12:00:00Z"));

        Assert.True(observation.IsConflict);
        Assert.Contains("this computer's MAC", observation.Warning);
    }

    [Fact]
    public void Observe_DeduplicatesRepeatedConflictWarnings()
    {
        var monitor = new ArpIdentityMonitor();
        var ip = IPAddress.Parse("192.168.31.20");
        var firstMac = PhysicalAddress.Parse("AABBCCDDEEFF");
        var secondMac = PhysicalAddress.Parse("AABBCCDDEE01");
        var now = DateTimeOffset.Parse("2026-11-06T12:00:00Z");

        _ = monitor.Observe(Frame(ip, firstMac), ControllerIp, ControllerMac, now);
        var firstWarning = monitor.Observe(
            Frame(ip, secondMac),
            ControllerIp,
            ControllerMac,
            now.AddSeconds(5));
        var repeated = monitor.Observe(
            Frame(ip, secondMac),
            ControllerIp,
            ControllerMac,
            now.AddSeconds(10));

        Assert.True(firstWarning.IsConflict);
        Assert.True(repeated.IsConflict);
        Assert.NotNull(firstWarning.Warning);
        Assert.Null(repeated.Warning);
    }

    [Fact]
    public void Observe_DoesNotFlagStableAddressPair()
    {
        var monitor = new ArpIdentityMonitor();
        var frame = Frame(
            IPAddress.Parse("192.168.31.20"),
            PhysicalAddress.Parse("AABBCCDDEEFF"));
        var now = DateTimeOffset.Parse("2026-11-06T12:00:00Z");

        Assert.False(monitor.Observe(frame, ControllerIp, ControllerMac, now).IsConflict);
        Assert.False(monitor.Observe(
            frame,
            ControllerIp,
            ControllerMac,
            now.AddSeconds(5)).IsConflict);
    }

    private static ArpFrameInfo Frame(IPAddress address, PhysicalAddress mac) =>
        new(ArpOperation.Reply, mac, mac, address, ControllerMac, ControllerIp);
}
