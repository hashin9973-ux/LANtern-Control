using System.Diagnostics;
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
    Ssdp,
    MdnsServiceBrowse,
}

public sealed record DiscoveredHost(
    IPAddress Address,
    HostDiscoveryMethod Method,
    long? RoundTripTimeMs = null,
    string? HostName = null);

public sealed record LocalHostDiscoveryResult(
    IReadOnlyList<DiscoveredHost> Hosts,
    int CandidateHosts,
    int SkippedRecentlyObserved = 0,
    int ProbeAttempts = 0,
    bool RateLimited = false)
{
    public int IcmpHosts => Hosts.Count(host => host.Method == HostDiscoveryMethod.Icmp);

    public int TcpHosts => Hosts.Count(host => host.Method == HostDiscoveryMethod.Tcp);

    public int NetBiosHosts => Hosts.Count(host => host.Method == HostDiscoveryMethod.NetBios);

    public int MdnsHosts => Hosts.Count(host => host.Method == HostDiscoveryMethod.Mdns);

    public int SsdpHosts => Hosts.Count(host => host.Method == HostDiscoveryMethod.Ssdp);

    public int MdnsServiceHosts =>
        Hosts.Count(host => host.Method == HostDiscoveryMethod.MdnsServiceBrowse);

    public string StatusMessage => RateLimited
        ? $"Supplemental protocol discovery skipped for {CandidateHosts} unconfirmed candidate(s): " +
          "this adapter was scanned less than 60 seconds ago."
        : CandidateHosts == 0
            ? SkippedRecentlyObserved > 0
                ? $"No supplemental probes were sent; {SkippedRecentlyObserved} local address(es) " +
                  "already had recent reachability evidence."
                : "No additional local IPv4 candidates were available for supplemental discovery."
            : $"Independent host discovery: {Hosts.Count} live IP endpoint(s) from " +
              $"{CandidateHosts} unconfirmed local candidate(s); " +
              $"{SkippedRecentlyObserved} recently observed address(es) skipped. " +
              $"Sent {ProbeAttempts} paced discovery query/probe(s) " +
              "(at least 5 ms between starts, at most 200 starts per second, " +
              "up to two link-local multicast queries, then no more than 5 direct probes " +
              "per remaining address, at most 64 concurrent hosts, " +
              "and one pass per minute). " +
              $"SSDP {SsdpHosts}, DNS-SD/mDNS {MdnsServiceHosts}, ICMP {IcmpHosts}, " +
              $"TCP {TcpHosts}, NetBIOS {NetBiosHosts}, reverse mDNS {MdnsHosts}.";
}

/// <summary>
/// Performs a supplemental, explicitly requested reachability check for local
/// IPv4 addresses that did not already produce recent ARP or traffic evidence.
/// Probes share one global pacer and are bounded per host. This service is never
/// started by the background monitoring loop.
/// </summary>
public sealed class LocalHostDiscoveryService
{
    private const int MaximumConcurrentHosts = 64;
    private const int PingTimeoutMilliseconds = 200;
    private const int TcpTimeoutMilliseconds = 100;

    private static readonly int[] CommonTcpPorts = [443, 80];
    // Supplemental discovery is paced globally to at most 200 starts per second.
    private static readonly TimeSpan ProbeSpacing = TimeSpan.FromMilliseconds(5);
    private static readonly long ProbeSpacingTimestampTicks =
        (long)(ProbeSpacing.TotalSeconds * Stopwatch.Frequency);

    private readonly SemaphoreSlim scanSync = new(1, 1);
    private readonly SemaphoreSlim probeStartSync = new(1, 1);
    private readonly Dictionary<string, DateTimeOffset> lastScanStartedAt =
        new(StringComparer.Ordinal);
    private readonly LocalMulticastDiscoveryService multicastDiscoveryService = new();
    private long nextProbeTimestamp;

    public async Task<LocalHostDiscoveryResult> ScanAsync(
        AdapterProfile adapter,
        IEnumerable<IPAddress>? recentlyObservedAddresses = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(adapter);

        await scanSync.WaitAsync(cancellationToken);
        try
        {
            var allTargets = DeviceProbePolicy.GetDiscoveryTargets(adapter);
            var targets = DeviceProbePolicy.GetProtocolDiscoveryTargets(
                adapter,
                recentlyObservedAddresses ?? []);
            var skippedRecentlyObserved = allTargets.Count - targets.Count;
            if (targets.Count == 0)
            {
                return new LocalHostDiscoveryResult(
                    [],
                    0,
                    skippedRecentlyObserved);
            }

            var scanStartedAt = DateTimeOffset.UtcNow;
            if (lastScanStartedAt.TryGetValue(adapter.Id, out var previousScanAt) &&
                !DeviceProbePolicy.IsDiscoveryScanDue(previousScanAt, scanStartedAt))
            {
                return new LocalHostDiscoveryResult(
                    [],
                    targets.Count,
                    skippedRecentlyObserved,
                    RateLimited: true);
            }

            // Record the start, not completion, so concurrent callers and cancelled
            // scans cannot immediately start another full protocol pass.
            lastScanStartedAt[adapter.Id] = scanStartedAt;

            var probeAttempts = 0;
            void CountProbeAttempt() => Interlocked.Increment(ref probeAttempts);

            // First ask the local link for advertised UPnP and DNS-SD services.
            // Hosts found this way are removed from the subsequent per-address
            // fallback list, avoiding duplicate traffic to those devices.
            var multicastHosts = await multicastDiscoveryService.ScanAsync(
                adapter,
                targets.ToHashSet(),
                (send, token) => RunPacedSendAsync(send, token, CountProbeAttempt),
                cancellationToken);

            var multicastResponders = multicastHosts
                .Select(host => host.Address)
                .ToHashSet();
            var remainingTargets = targets
                .Where(address => !multicastResponders.Contains(address))
                .ToArray();

            using var hostLimiter = new SemaphoreSlim(MaximumConcurrentHosts);
            var probes = remainingTargets.Select(address =>
                ProbeHostWithThrottleAsync(
                    address,
                    hostLimiter,
                    cancellationToken,
                    CountProbeAttempt));
            var results = await Task.WhenAll(probes);

            cancellationToken.ThrowIfCancellationRequested();

            var hosts = multicastHosts
                .Concat(results.Where(host => host is not null).Select(host => host!))
                .OrderBy(host => host.Address.GetAddressBytes(), ByteArrayComparer.Instance)
                .ToArray();

            return new LocalHostDiscoveryResult(
                hosts,
                targets.Count,
                skippedRecentlyObserved,
                Volatile.Read(ref probeAttempts));
        }
        finally
        {
            scanSync.Release();
        }
    }

    public static bool IsDefinitiveTcpResponse(SocketError error) =>
        error is SocketError.ConnectionRefused or SocketError.ConnectionReset;

    private async Task<DiscoveredHost?> ProbeHostWithThrottleAsync(
        IPAddress address,
        SemaphoreSlim limiter,
        CancellationToken cancellationToken,
        Action onProbeStarted)
    {
        await limiter.WaitAsync(cancellationToken);
        try
        {
            var pingTime = await TryPingAsync(address, cancellationToken, onProbeStarted);
            if (pingTime is long latency)
            {
                return new DiscoveredHost(
                    address,
                    HostDiscoveryMethod.Icmp,
                    latency);
            }

            if (await TryTcpAsync(address, cancellationToken, onProbeStarted))
            {
                return new DiscoveredHost(address, HostDiscoveryMethod.Tcp);
            }

            cancellationToken.ThrowIfCancellationRequested();
            var netBiosName = await TryResolveNetBiosAsync(
                address,
                cancellationToken,
                onProbeStarted);
            if (!string.IsNullOrWhiteSpace(netBiosName))
            {
                return new DiscoveredHost(
                    address,
                    HostDiscoveryMethod.NetBios,
                    HostName: netBiosName);
            }

            cancellationToken.ThrowIfCancellationRequested();
            var mdnsName = await TryResolveMdnsAsync(
                address,
                cancellationToken,
                onProbeStarted);
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

    private async Task<long?> TryPingAsync(
        IPAddress address,
        CancellationToken cancellationToken,
        Action onProbeStarted)
    {
        using var ping = new Ping();
        try
        {
            var reply = await RunPacedOperationAsync(
                () => ping.SendPingAsync(
                    address,
                    TimeSpan.FromMilliseconds(PingTimeoutMilliseconds),
                    cancellationToken: cancellationToken),
                cancellationToken,
                onProbeStarted);

            return reply.Status == IPStatus.Success
                ? reply.RoundtripTime
                : null;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is PingException or SocketException)
        {
            return null;
        }
    }

    private async Task<bool> TryTcpAsync(
        IPAddress address,
        CancellationToken cancellationToken,
        Action onProbeStarted)
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
                var connected = await RunPacedOperationAsync(
                    async () =>
                    {
                        await socket.ConnectAsync(address, port, timeout.Token);
                        return socket.Connected;
                    },
                    cancellationToken,
                    onProbeStarted);
                if (connected)
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
                // A filtered or silent port is inconclusive, not evidence of a live host.
            }
            catch (SocketException exception) when (
                IsDefinitiveTcpResponse(exception.SocketErrorCode))
            {
                // A TCP reset/refusal is an explicit response from the target.
                return true;
            }
            catch (SocketException)
            {
                // Routing and network errors are inconclusive; try the one alternate port.
            }
            catch (ObjectDisposedException) when (cancellationToken.IsCancellationRequested)
            {
                throw new OperationCanceledException(cancellationToken);
            }
        }

        return false;
    }

    private async Task<string?> TryResolveNetBiosAsync(
        IPAddress address,
        CancellationToken cancellationToken,
        Action onProbeStarted)
    {
        try
        {
            var name = await NetBiosNameResolver.ResolveAsync(
                address,
                cancellationToken,
                (send, token) => RunPacedSendAsync(send, token, onProbeStarted));
            cancellationToken.ThrowIfCancellationRequested();
            return name;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is SocketException or TimeoutException)
        {
            return null;
        }
    }

    private async Task<string?> TryResolveMdnsAsync(
        IPAddress address,
        CancellationToken cancellationToken,
        Action onProbeStarted)
    {
        try
        {
            var name = await MdnsNameResolver.ResolveAsync(
                address,
                cancellationToken,
                (send, token) => RunPacedSendAsync(send, token, onProbeStarted));
            cancellationToken.ThrowIfCancellationRequested();
            return name;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is SocketException or TimeoutException)
        {
            return null;
        }
    }

    private async Task<T> RunPacedOperationAsync<T>(
        Func<Task<T>> startOperation,
        CancellationToken cancellationToken,
        Action onProbeStarted)
    {
        Task<T> operation;
        await probeStartSync.WaitAsync(cancellationToken);
        try
        {
            await WaitForNextProbeSlotAsync(cancellationToken);
            onProbeStarted();
            operation = startOperation();
            nextProbeTimestamp = Stopwatch.GetTimestamp() + ProbeSpacingTimestampTicks;
        }
        finally
        {
            probeStartSync.Release();
        }

        return await operation.ConfigureAwait(false);
    }

    private async Task RunPacedSendAsync(
        Func<Task> startSend,
        CancellationToken cancellationToken,
        Action onProbeStarted)
    {
        Task send;
        await probeStartSync.WaitAsync(cancellationToken);
        try
        {
            await WaitForNextProbeSlotAsync(cancellationToken);
            onProbeStarted();
            send = startSend();
            nextProbeTimestamp = Stopwatch.GetTimestamp() + ProbeSpacingTimestampTicks;
        }
        finally
        {
            probeStartSync.Release();
        }

        await send.ConfigureAwait(false);
    }

    private async Task WaitForNextProbeSlotAsync(CancellationToken cancellationToken)
    {
        var remainingTicks = nextProbeTimestamp - Stopwatch.GetTimestamp();
        if (remainingTicks > 0)
        {
            var delaySeconds = remainingTicks / (double)Stopwatch.Frequency;
            await Task.Delay(TimeSpan.FromSeconds(delaySeconds), cancellationToken);
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
