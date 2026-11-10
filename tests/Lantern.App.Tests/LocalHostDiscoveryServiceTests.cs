using System.Net.Sockets;
using Lantern.App.Services;
using Xunit;

namespace Lantern.App.Tests;

public sealed class LocalHostDiscoveryServiceTests
{
    [Theory]
    [InlineData(SocketError.ConnectionRefused, true)]
    [InlineData(SocketError.ConnectionReset, true)]
    [InlineData(SocketError.TimedOut, false)]
    [InlineData(SocketError.NetworkUnreachable, false)]
    [InlineData(SocketError.HostUnreachable, false)]
    [InlineData(SocketError.AddressNotAvailable, false)]
    public void IsDefinitiveTcpResponse_OnlyAcceptsAnExplicitTargetResponse(
        SocketError error,
        bool expected)
    {
        Assert.Equal(expected, LocalHostDiscoveryService.IsDefinitiveTcpResponse(error));
    }

    [Fact]
    public void StatusMessage_ReportsEachDiscoveryProtocolSeparately()
    {
        var result = new LocalHostDiscoveryResult(
        [
            new DiscoveredHost(
                System.Net.IPAddress.Parse("192.168.31.20"),
                HostDiscoveryMethod.Icmp,
                3),
            new DiscoveredHost(
                System.Net.IPAddress.Parse("192.168.31.21"),
                HostDiscoveryMethod.Tcp),
            new DiscoveredHost(
                System.Net.IPAddress.Parse("192.168.31.22"),
                HostDiscoveryMethod.NetBios,
                HostName: "OFFICE-PC"),
            new DiscoveredHost(
                System.Net.IPAddress.Parse("192.168.31.23"),
                HostDiscoveryMethod.Mdns,
                HostName: "speaker"),
            new DiscoveredHost(
                System.Net.IPAddress.Parse("192.168.31.24"),
                HostDiscoveryMethod.Ssdp),
            new DiscoveredHost(
                System.Net.IPAddress.Parse("192.168.31.25"),
                HostDiscoveryMethod.MdnsServiceBrowse),
        ],
        CandidateHosts: 252);

        Assert.Equal(6, result.Hosts.Count);
        Assert.Equal(1, result.IcmpHosts);
        Assert.Equal(1, result.TcpHosts);
        Assert.Equal(1, result.NetBiosHosts);
        Assert.Equal(1, result.MdnsHosts);
        Assert.Equal(1, result.SsdpHosts);
        Assert.Equal(1, result.MdnsServiceHosts);
        Assert.Contains("252 unconfirmed local candidate(s)", result.StatusMessage, StringComparison.Ordinal);
        Assert.Contains("at least 5 ms between starts", result.StatusMessage, StringComparison.Ordinal);
        Assert.Contains("at most 200 starts per second", result.StatusMessage, StringComparison.Ordinal);
        Assert.Contains("up to two link-local multicast queries", result.StatusMessage, StringComparison.Ordinal);
        Assert.Contains("at most 64 concurrent hosts", result.StatusMessage, StringComparison.Ordinal);
        Assert.Contains("no more than 5 direct probes per remaining address", result.StatusMessage, StringComparison.Ordinal);
        Assert.Contains("SSDP 1, DNS-SD/mDNS 1, ICMP 1, TCP 1, NetBIOS 1, reverse mDNS 1", result.StatusMessage, StringComparison.Ordinal);
    }

    [Fact]
    public void StatusMessage_ExplainsWhenRecentEvidenceMakesFallbackProbesUnnecessary()
    {
        var result = new LocalHostDiscoveryResult(
            [],
            CandidateHosts: 0,
            SkippedRecentlyObserved: 252);

        Assert.Contains("No supplemental probes were sent", result.StatusMessage, StringComparison.Ordinal);
        Assert.Contains("252 local address(es)", result.StatusMessage, StringComparison.Ordinal);
    }

    [Fact]
    public void StatusMessage_ReportsPacingWithoutAHiddenOneMinuteThrottle()
    {
        var result = new LocalHostDiscoveryResult(
            [new DiscoveredHost(
                System.Net.IPAddress.Parse("192.168.31.20"),
                HostDiscoveryMethod.Icmp,
                4)],
            CandidateHosts: 40,
            SkippedRecentlyObserved: 212,
            ProbeAttempts: 1);

        Assert.Contains("at most 200 starts per second", result.StatusMessage, StringComparison.Ordinal);
        Assert.DoesNotContain("one pass per minute", result.StatusMessage, StringComparison.Ordinal);
    }

}
