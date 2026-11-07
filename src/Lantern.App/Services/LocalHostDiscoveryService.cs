using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using Lantern.Core.Networking;

namespace Lantern.App.Services;

public enum HostDiscoveryMethod
{
    Icmp,
    Tcp,
    NetBios,
    Mdns,
}

public sealed record DiscoveredHost(
    IPAddress Address,
    HostDiscoveryMethod Method,
    long? RoundTripTimeMs = null,
    string? HostName = null);

public sealed record LocalHostDiscoveryResult(
    IReadOnlyList<DiscoveredHost> Hosts,
    int CandidateHosts)
{
    public int IcmpHosts => Hosts.Count(host => host.Method == HostDiscoveryMethod.Icmp);

    public int TcpHosts => Hosts.Count(host => host.Method == HostDiscoveryMethod.Tcp);

    public int NetBiosHosts => Hosts.Count(host => host.Method == HostDiscoveryMethod.NetBios);

    public int MdnsHosts => Hosts.Count(host => host.Method == HostDiscoveryMethod.Mdns);

    public string StatusMessage =>
        $"Independent host discovery: {Hosts.Count} live IP endpoint(s) from {CandidateHosts} local candidates " +
        $"(ICMP {IcmpHosts}, TCP {TcpHosts}, NetBIOS {NetBiosHosts}, mDNS {MdnsHosts}).";
}

/// <summary>
/// Confirms local IPv4 hosts independently of the packet-capture ARP sweep.
/// ICMP is tried first, followed by bounded TCP connect checks and then
/// device-name protocols that can also provide positive liveness evidence.
/// The target list is always obtained from the selected adapter's local range.
/// </summary>
public sealed class LocalHostDiscoveryService
{
    private const int MaximumConcurrentHosts = 48;
    private const int PingTimeoutMilliseconds = 400;
    private const int PingAttempts = 2;
    private const int PingRetryDelayMilliseconds = 60;
    private const int TcpTimeoutMilliseconds = 225;

    private static readonly int[] CommonTcpPorts =
    [
        80,   // HTTP
        443,  // HTTPS
        445,  // SMB
        22,   // SSH
        139,  // NetBIOS session service
        3389, // Remote desktop
        554,  // RTSP
        8080, // Alternate HTTP
    ];

    public async Task<LocalHostDiscoveryResult> ScanAsync(
        AdapterProfile adapter,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(adapter);

        var targets = DeviceProbePolicy.GetDiscoveryTargets(adapter);
        using var hostLimiter = new SemaphoreSlim(MaximumConcurrentHosts);
        var probes = targets.Select(address =>
            ProbeHostWithThrottleAsync(address, hostLimiter, cancellationToken));
        var results = await Task.WhenAll(probes);

        cancellationToken.ThrowIfCancellationRequested();

        var hosts = results
            .Where(host => host is not null)
            .Select(host => host!)
            .OrderBy(host => host.Address.GetAddressBytes(), ByteArrayComparer.Instance)
            .ToArray();

        return new LocalHostDiscoveryResult(hosts, targets.Count);
    }

    public static bool IsDefinitiveTcpResponse(SocketError error) =>
        error is SocketError.ConnectionRefused or SocketError.ConnectionReset;

    private static async Task<DiscoveredHost?> ProbeHostWithThrottleAsync(
        IPAddress address,
        SemaphoreSlim limiter,
        CancellationToken cancellationToken)
    {
        await limiter.WaitAsync(cancellationToken);
        try
        {
            var pingTime = await TryPingAsync(address, cancellationToken);
            if (pingTime is long latency)
            {
                return new DiscoveredHost(
                    address,
                    HostDiscoveryMethod.Icmp,
                    latency);
            }

            if (await TryTcpAsync(address, cancellationToken))
            {
                return new DiscoveredHost(address, HostDiscoveryMethod.Tcp);
            }

            cancellationToken.ThrowIfCancellationRequested();
            string? netBiosName = await TryResolveNetBiosAsync(address, cancellationToken);
            if (!string.IsNullOrWhiteSpace(netBiosName))
            {
                return new DiscoveredHost(
                    address,
                    HostDiscoveryMethod.NetBios,
                    HostName: netBiosName);
            }

            cancellationToken.ThrowIfCancellationRequested();
            string? mdnsName = await TryResolveMdnsAsync(address, cancellationToken);
            return string.IsNullOrWhiteSpace(mdnsName)
                ? null
                : new DiscoveredHost(
                    address,
                    HostDiscoveryMethod.Mdns,
                    HostName: mdnsName);
        }
        finally
        {
            limiter.Release();
        }
    }

    private static async Task<long?> TryPingAsync(
        IPAddress address,
        CancellationToken cancellationToken)
    {
        using var ping = new Ping();
        long latencyTotal = 0;
        var replies = 0;

        for (var attempt = 0; attempt < PingAttempts; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (attempt > 0)
            {
                await Task.Delay(PingRetryDelayMilliseconds, cancellationToken);
            }

            try
            {
                var reply = await ping.SendPingAsync(
                    address,
                    TimeSpan.FromMilliseconds(PingTimeoutMilliseconds),
                    cancellationToken: cancellationToken);
                if (reply.Status == IPStatus.Success)
                {
                    latencyTotal += reply.RoundtripTime;
                    replies++;
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception exception) when (
                exception is PingException or SocketException)
            {
                // One failed ICMP attempt is inconclusive; the next discovery
                // method still gets a chance to confirm the address.
            }
        }

        return replies == 0
            ? null
            : (long)Math.Round(
                (double)latencyTotal / replies,
                MidpointRounding.AwayFromZero);
    }

    private static async Task<bool> TryTcpAsync(
        IPAddress address,
        CancellationToken cancellationToken)
    {
        foreach (var port in CommonTcpPorts)
        {
            cancellationToken.ThrowIfCancellationRequested();
            using var socket = new Socket(
                AddressFamily.InterNetwork,
                SocketType.Stream,
                ProtocolType.Tcp);
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken);
            timeout.CancelAfter(TcpTimeoutMilliseconds);

            try
            {
                await socket.ConnectAsync(address, port, timeout.Token);
                if (socket.Connected)
                {
                    return true;
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (OperationCanceledException)
            {
                // A filtered or silent port is not evidence that a host is online.
            }
            catch (SocketException exception) when (
                IsDefinitiveTcpResponse(exception.SocketErrorCode))
            {
                // A TCP reset/refusal is an explicit response from the target.
                return true;
            }
            catch (SocketException)
            {
                // Network/routing errors are inconclusive; try the next port.
            }
            catch (ObjectDisposedException) when (cancellationToken.IsCancellationRequested)
            {
                throw new OperationCanceledException(cancellationToken);
            }
        }

        return false;
    }

    private static async Task<string?> TryResolveNetBiosAsync(
        IPAddress address,
        CancellationToken cancellationToken)
    {
        try
        {
            var name = await NetBiosNameResolver.ResolveAsync(address, cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();
            return name;
        }
        catch (Exception exception) when (
            exception is SocketException or TimeoutException)
        {
            return null;
        }
    }

    private static async Task<string?> TryResolveMdnsAsync(
        IPAddress address,
        CancellationToken cancellationToken)
    {
        try
        {
            var name = await MdnsNameResolver.ResolveAsync(address, cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();
            return name;
        }
        catch (Exception exception) when (
            exception is SocketException or TimeoutException)
        {
            return null;
        }
    }

    private sealed class ByteArrayComparer : IComparer<byte[]>
    {
        public static ByteArrayComparer Instance { get; } = new();

        public int Compare(byte[]? left, byte[]? right)
        {
            if (ReferenceEquals(left, right))
            {
                return 0;
            }

            if (left is null)
            {
                return -1;
            }

            if (right is null)
            {
                return 1;
            }

            for (var index = 0; index < Math.Min(left.Length, right.Length); index++)
            {
                var comparison = left[index].CompareTo(right[index]);
                if (comparison != 0)
                {
                    return comparison;
                }
            }

            return left.Length.CompareTo(right.Length);
        }
    }
}
