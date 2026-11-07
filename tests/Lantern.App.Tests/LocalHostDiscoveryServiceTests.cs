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
        ],
        CandidateHosts: 252);

        Assert.Equal(4, result.Hosts.Count);
        Assert.Equal(1, result.IcmpHosts);
        Assert.Equal(1, result.TcpHosts);
        Assert.Equal(1, result.NetBiosHosts);
        Assert.Equal(1, result.MdnsHosts);
        Assert.Contains("252 local candidates", result.StatusMessage, StringComparison.Ordinal);
        Assert.Contains("ICMP 1, TCP 1, NetBIOS 1, mDNS 1", result.StatusMessage, StringComparison.Ordinal);
    }
}
