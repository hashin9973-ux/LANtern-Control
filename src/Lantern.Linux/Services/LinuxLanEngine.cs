using System.Collections.Concurrent;
using System.Net;
using System.Net.NetworkInformation;
using Lantern.App.Services;
using Lantern.Core.Control;
using Lantern.Core.Devices;
using Lantern.Core.Networking;
using SharpPcap;
using SharpPcap.LibPcap;

namespace Lantern.Linux.Services;

public sealed class LinuxLanEngine : IAsyncDisposable
{
    private readonly DeviceRegistry registry;
    private readonly TrafficPolicy policy;
    private readonly LinuxFrameDeduplicator frameDeduplicator = new();
    private readonly object injectionSync = new();
    private readonly SemaphoreSlim refreshSync = new(1, 1);
    private readonly SemaphoreSlim stopSync = new(1, 1);
    private readonly ClientMappingCache clientMappings = new();
    private readonly ArpIdentityMonitor identityMonitor = new();
    private readonly ConcurrentDictionary<IPAddress, DateTimeOffset> lastPresenceProbeAt = new();
    private DateTimeOffset lastPresenceProbeBatchAt = DateTimeOffset.MinValue;
    private DateTimeOffset lastDiscoveryProbeBatchAt = DateTimeOffset.MinValue;
    private string? presenceProbeAdapterId;
    private readonly ResolvedDeviceNameClaims resolvedNameClaims = new(Dns.GetHostName());
    private ConcurrentDictionary<IPAddress, PhysicalAddress> clients => clientMappings.Mappings;
    private readonly ConcurrentDictionary<string, byte> resolvingNames =
        new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, string> learnedHostNames =
        new(StringComparer.OrdinalIgnoreCase);
    private CancellationTokenSource? engineCancellation;
    private Task? backgroundTask;
    private LibPcapLiveDevice? arpDevice;
    private LibPcapLiveDevice? forwardingDevice;
    private LibPcapLiveDevice? injectionDevice;
    private AdapterProfile? profile;
    private PhysicalAddress? gatewayMac;
    private FrameRouter? frameRouter;
    private LinuxFramePacer? framePacer;
    private LinuxOffloadSession? offloadSession;
    private LinuxIpForwardingSession? ipForwardingSession;
    private TaskCompletionSource<PhysicalAddress>? gatewayResolution;
    private KnownDeviceHint[] knownDeviceHints = [];
    private AdapterProfile? temporaryProbeProfile;
    private HashSet<IPAddress>? temporaryProbeTargets;
    private ConcurrentDictionary<IPAddress, byte>? temporaryProbeResponders;
    private ArpIdentityMonitor? temporaryProbeIdentityMonitor;
    private string[] rejectedResolvedNames = [];
    private volatile bool controlling;
    private volatile bool restoring;
    private string? backgroundFailure;
    private long forwardedPacketCount;
    private long droppedPacketCount;
    private long suppressedDuplicatePacketCount;

    public LinuxLanEngine(DeviceRegistry registry, TrafficPolicy policy)
    {
        this.registry = registry;
        this.policy = policy;
    }

    public bool IsRunning =>
        arpDevice is not null || forwardingDevice is not null || injectionDevice is not null;
    public bool IsControlling => controlling;
    public long ForwardedPacketCount => Interlocked.Read(ref forwardedPacketCount);
    public long DroppedPacketCount => Interlocked.Read(ref droppedPacketCount);
    public long SuppressedDuplicatePacketCount =>
        Interlocked.Read(ref suppressedDuplicatePacketCount);
    public string DriverName { get; private set; } = "libpcap not started";

    public event EventHandler<string>? StatusChanged;
    public event EventHandler<LinuxEngineStateChangedEventArgs>? StateChanged;
    public event EventHandler<DeviceIdentityLearnedEventArgs>? DeviceIdentityLearned;
    public event EventHandler<DeviceDomainObservedEventArgs>? DeviceDomainObserved;

    public event EventHandler<string>? IdentityAlertDetected;

    public void ForgetDevice(PhysicalAddress macAddress)
    {
        foreach (var address in clientMappings.RemoveByMac(macAddress))
        {
            frameRouter?.RemoveClient(address);
            lastPresenceProbeAt.TryRemove(address, out _);
        }
    }

    public void ReplaceKnownDeviceHints(IEnumerable<KnownDeviceHint> hints)
    {
        ArgumentNullException.ThrowIfNull(hints);
        knownDeviceHints = hints
            .Where(hint => !hint.MacAddress.Equals(PhysicalAddress.None))
            .DistinctBy(hint => TrafficPolicy.NormalizeMac(hint.MacAddress.ToString()))
            .ToArray();
    }

    public void ReplaceRejectedResolvedNames(IEnumerable<string> names)
    {
        ArgumentNullException.ThrowIfNull(names);
        rejectedResolvedNames = names.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        resolvedNameClaims.Reset(rejectedResolvedNames);
    }

    public async Task StartAsync(AdapterProfile adapter, CancellationToken cancellationToken)
    {
        if (IsRunning)
        {
            return;
        }

        profile = adapter;
        clientMappings.BeginAdapter(adapter.Id);
        var clients = clientMappings.Mappings;
        resolvedNameClaims.Reset(rejectedResolvedNames);
        resolvingNames.Clear();
        learnedHostNames.Clear();
        registry.BeginSession();
        identityMonitor.Reset();
        SeedRememberedInventory();

        restoring = false;
        backgroundFailure = null;
        Interlocked.Exchange(ref forwardedPacketCount, 0);
        Interlocked.Exchange(ref droppedPacketCount, 0);
        Interlocked.Exchange(ref suppressedDuplicatePacketCount, 0);
        frameDeduplicator.Clear();
        gatewayResolution = new TaskCompletionSource<PhysicalAddress>(
            TaskCreationOptions.RunContinuationsAsynchronously);

        var captureDevice = LibPcapLiveDeviceList.Instance
            .FirstOrDefault(candidate => candidate.MacAddress?.Equals(adapter.LocalMac) == true)
            ?? throw new InvalidOperationException(
                $"libpcap could not match the Linux adapter '{adapter.Name}'.");

        try
        {
            RaiseStatus($"Preparing adapter {adapter.Name} for packet forwarding...");
            ipForwardingSession = await LinuxIpForwardingManager.DisableAsync(
                cancellationToken);
            offloadSession = await LinuxOffloadManager.DisableAsync(
                adapter.Name,
                cancellationToken);

            arpDevice = captureDevice;
            arpDevice.OnPacketArrival += OnArpPacketArrival;
            arpDevice.Open(LinuxCaptureConfiguration.CreateForArpDiscovery());
            // DHCP is broadcast before a client necessarily exists in our ARP
            // table. Capture it alongside ARP so a device name learned once can
            // be persisted and reused across future launches/IP changes.
            arpDevice.Filter = "arp or (udp and (port 67 or port 68))";
            arpDevice.StartCapture();

            forwardingDevice = new LibPcapLiveDevice(
                captureDevice.Interface ??
                throw new InvalidOperationException("The capture adapter has no interface."));
            forwardingDevice.Open(LinuxCaptureConfiguration.CreateForForwarding());
            forwardingDevice.Filter = LinuxCaptureFilter.ForForwarding(adapter.LocalMac);

            // Capture and injection use different native pcap handles. Calling
            // pcap_next_ex and pcap_sendpacket concurrently on one handle is not
            // portable and can stop physical Wi-Fi adapters even when a veth test
            // passes. All emitted ARP and forwarded Ethernet frames are serialized
            // through this dedicated injection handle.
            injectionDevice = new LibPcapLiveDevice(
                captureDevice.Interface ??
                throw new InvalidOperationException("The capture adapter has no interface."));
            injectionDevice.Open(LinuxCaptureConfiguration.CreateForForwarding());
            DriverName = captureDevice.Description ?? captureDevice.Name;
            RaiseStatus($"Resolving gateway {adapter.GatewayAddress}...");
            SendArpPacket(EthernetFrameCodec.BuildArpRequest(
                adapter.LocalMac,
                adapter.LocalAddress,
                adapter.GatewayAddress));

            gatewayMac = await gatewayResolution.Task.WaitAsync(
                TimeSpan.FromSeconds(4),
                cancellationToken);
            registry.Observe(
                adapter.GatewayAddress,
                gatewayMac,
                DateTimeOffset.UtcNow,
                "Gateway");
            frameRouter = new FrameRouter(
                adapter.LocalMac,
                adapter.LocalAddress,
                gatewayMac,
                clients,
                policy,
                enforceRateLimits: false);
            framePacer = new LinuxFramePacer(
                policy,
                frame =>
                {
                    SendForwardingPacket(frame);
                    Interlocked.Increment(ref forwardedPacketCount);
                },
                frameDropped: () => Interlocked.Increment(ref droppedPacketCount),
                failed: exception =>
                {
                    HandleBackgroundFailure("Traffic pacing failed", exception);
                });

            engineCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            controlling = true;
            var forwarderStarted = new TaskCompletionSource(
                TaskCreationOptions.RunContinuationsAsynchronously);
            var forwardingTask = Task.Run(
                () => RunForwardingLoop(engineCancellation.Token, forwarderStarted));
            await forwarderStarted.Task.WaitAsync(TimeSpan.FromSeconds(2), cancellationToken);
            await RefreshNeighborsAsync(cancellationToken);
            PoisonClients();
            backgroundTask = Task.WhenAll(
                forwardingTask,
                RunMaintenanceAsync(engineCancellation.Token));
            const string activeMessage =
                "Linux control active - live traffic is routed through this computer.";
            RaiseStatus(activeMessage);
            RaiseStateChanged(true, activeMessage);
        }
        catch (Exception exception)
        {
            // StopAsync performs the safety restoration, but it must not replace
            // the startup exception with a generic restoration message. The UI
            // receives StateChanged asynchronously, so preserving the failure here
            // also prevents that queued notification from hiding the real cause.
            Interlocked.CompareExchange(
                ref backgroundFailure,
                $"Startup failed: {exception.Message}",
                null);
            await StopAsync();
            throw;
        }
    }

    public Task<DiscoveryRefreshResult> RefreshNeighborsAsync(
        CancellationToken cancellationToken = default)
    {
        var activeProfile = profile ??
            throw new InvalidOperationException("Select an adapter before scanning devices.");
        return ScanDevicesAsync(activeProfile, cancellationToken);
    }

    public async Task<DiscoveryRefreshResult> ScanDevicesAsync(
        AdapterProfile selectedAdapter,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(selectedAdapter);
        await refreshSync.WaitAsync(cancellationToken);
        try
        {
            SeedRememberedInventory();
            var cached = await LinuxArpCache.ReadAsync(
                selectedAdapter.Name,
                selectedAdapter.LocalAddress,
                selectedAdapter.PrefixLength,
                cancellationToken);
            var imported = ImportCachedNeighbors(selectedAdapter, cached);
            var probesSent = 0;
            var devicesResponded = 0;
            var retryRequestsSent = 0;
            var candidateHosts = 0;
            string? probeWarning = null;
            try
            {
                var probeResult = await ProbeAddressesAsync(
                    selectedAdapter,
                    force: true,
                    cancellationToken,
                    discoverSubnet: true);
                probesSent = probeResult.RequestsSent;
                devicesResponded = probeResult.DevicesResponded;
                retryRequestsSent = probeResult.RetryRequestsSent;
                candidateHosts = probeResult.CandidateHosts;
            }
            catch (Exception exception) when (
                !IsRunning && exception is not OperationCanceledException)
            {
                probeWarning = exception.Message;
            }

            return new DiscoveryRefreshResult(
                imported,
                registry.Peek().Count,
                probesSent,
                probeWarning,
                devicesResponded,
                retryRequestsSent,
                candidateHosts);
        }
        finally
        {
            refreshSync.Release();
        }
    }

    private void SeedRememberedInventory()
    {
        foreach (var hint in knownDeviceHints.Where(hint => hint.LastKnownIp is not null))
        {
            registry.Remember(
                hint.LastKnownIp!,
                hint.MacAddress,
                hint.LastSeenUtc ?? DateTimeOffset.MinValue,
                hint.HostName,
                hint.LastSeenUtc);
        }
    }

    private async Task<DiscoveryProbeResult> ProbeAddressesAsync(
        AdapterProfile activeProfile,
        bool force,
        CancellationToken cancellationToken,
        bool discoverSubnet = false)
    {
        if (!string.Equals(
                presenceProbeAdapterId,
                activeProfile.Id,
                StringComparison.Ordinal))
        {
            lastPresenceProbeAt.Clear();
            lastPresenceProbeBatchAt = DateTimeOffset.MinValue;
            lastDiscoveryProbeBatchAt = DateTimeOffset.MinValue;
            presenceProbeAdapterId = activeProfile.Id;
        }

        var now = DateTimeOffset.UtcNow;
        var previousBatchAt = discoverSubnet
            ? lastDiscoveryProbeBatchAt
            : lastPresenceProbeBatchAt;
        var minimumInterval = discoverSubnet
            ? DeviceProbePolicy.DiscoveryInterval
            : DeviceProbePolicy.ProbeInterval;
        if (previousBatchAt != DateTimeOffset.MinValue &&
            now >= previousBatchAt &&
            now - previousBatchAt < minimumInterval)
        {
            return DiscoveryProbeResult.Empty;
        }

        var targets = discoverSubnet
            ? DeviceProbePolicy.GetDiscoveryTargets(activeProfile)
            : DeviceProbePolicy.GetTargets(
                registry.Peek(),
                activeProfile,
                now,
                force,
                lastPresenceProbeAt);
        if (targets.Count == 0)
        {
            return DiscoveryProbeResult.Empty;
        }

        var requestSpacing = discoverSubnet
            ? DeviceProbePolicy.DiscoveryRequestSpacing
            : DeviceProbePolicy.RequestSpacing;
        Action<int, int>? progress = discoverSubnet
            ? (completed, total) => RaiseStatus(
                $"Local IPv4 discovery: checked {completed} of {total} host addresses.")
            : null;
        if (discoverSubnet)
        {
            RaiseStatus(
                $"Starting a paced local IPv4 discovery: 0 of {targets.Count} host addresses checked.");
        }

        var responders = new ConcurrentDictionary<IPAddress, byte>();

        void MarkBatchStarted()
        {
            if (discoverSubnet)
            {
                lastDiscoveryProbeBatchAt = DateTimeOffset.UtcNow;
            }
            else
            {
                lastPresenceProbeBatchAt = DateTimeOffset.UtcNow;
            }
        }

        void MarkBatchCompleted()
        {
            if (discoverSubnet)
            {
                lastDiscoveryProbeBatchAt = DateTimeOffset.UtcNow;
            }
        }

        async Task<DiscoveryProbeResult> SendBatchesAsync(
            Action<IPAddress, byte[]> sendProbe)
        {
            MarkBatchStarted();
            var firstPassSent = await SendPresenceProbesAsync(
                sendProbe,
                activeProfile,
                targets,
                cancellationToken,
                requestSpacing,
                progress);

            var retryTargets = discoverSubnet
                ? targets.Where(address => !responders.ContainsKey(address)).ToArray()
                : [];
            var retrySent = 0;
            if (retryTargets.Length > 0)
            {
                RaiseStatus(
                    $"Retrying {retryTargets.Length} addresses that did not answer the first ARP request.");
                retrySent = await SendPresenceProbesAsync(
                    sendProbe,
                    activeProfile,
                    retryTargets,
                    cancellationToken,
                    DeviceProbePolicy.DiscoveryRetrySpacing,
                    (completed, total) =>
                    {
                        if (completed % 20 == 0 || completed == total)
                        {
                            RaiseStatus(
                                $"Local IPv4 discovery retry: checked {completed} of {total} unanswered addresses.");
                        }
                    });
            }

            MarkBatchCompleted();
            return new DiscoveryProbeResult(
                firstPassSent + retrySent,
                retrySent,
                responders.Count,
                discoverSubnet ? targets.Count : 0);
        }

        if (arpDevice is not null && injectionDevice is not null)
        {
            if (discoverSubnet)
            {
                BeginTemporaryProbeContext(activeProfile, targets, responders, createIdentityMonitor: false);
            }

            try
            {
                return await SendBatchesAsync(
                    (address, bytes) =>
                    {
                        SendArpPacket(bytes);
                        lastPresenceProbeAt[address] = DateTimeOffset.UtcNow;
                    });
            }
            finally
            {
                if (discoverSubnet)
                {
                    EndTemporaryProbeContext();
                }
            }
        }

        var captureDevice = LibPcapLiveDeviceList.Instance
            .FirstOrDefault(candidate => candidate.MacAddress?.Equals(activeProfile.LocalMac) == true)
            ?? throw new InvalidOperationException(
                $"libpcap could not find adapter '{activeProfile.Name}' for device presence checks.");
        var probeInjector = new LibPcapLiveDevice(
            captureDevice.Interface ??
            throw new InvalidOperationException("The selected adapter has no libpcap interface."));

        BeginTemporaryProbeContext(activeProfile, targets, responders, createIdentityMonitor: true);
        captureDevice.OnPacketArrival += OnTemporaryPresencePacketArrival;
        var captureOpened = false;
        var injectorOpened = false;
        var captureStarted = false;
        try
        {
            captureDevice.Open(LinuxCaptureConfiguration.CreateForArpDiscovery());
            captureOpened = true;
            captureDevice.Filter = "arp";
            captureDevice.StartCapture();
            captureStarted = true;

            probeInjector.Open(LinuxCaptureConfiguration.CreateForForwarding());
            injectorOpened = true;

            return await SendBatchesAsync(
                (address, bytes) =>
                {
                    lock (injectionSync)
                    {
                        probeInjector.SendPacket(bytes);
                    }

                    lastPresenceProbeAt[address] = DateTimeOffset.UtcNow;
                });
        }
        finally
        {
            if (captureStarted)
            {
                try
                {
                    captureDevice.StopCapture();
                }
                catch (InvalidOperationException)
                {
                }
            }

            captureDevice.OnPacketArrival -= OnTemporaryPresencePacketArrival;
            if (captureOpened)
            {
                captureDevice.Close();
            }

            if (injectorOpened)
            {
                probeInjector.Close();
            }

            EndTemporaryProbeContext();
        }
    }

    private void BeginTemporaryProbeContext(
        AdapterProfile activeProfile,
        IReadOnlyList<IPAddress> targets,
        ConcurrentDictionary<IPAddress, byte> responders,
        bool createIdentityMonitor)
    {
        temporaryProbeProfile = activeProfile;
        temporaryProbeTargets = targets.ToHashSet();
        temporaryProbeIdentityMonitor = createIdentityMonitor
            ? new ArpIdentityMonitor()
            : null;
        temporaryProbeResponders = responders;
    }

    private void EndTemporaryProbeContext()
    {
        temporaryProbeProfile = null;
        temporaryProbeTargets = null;
        temporaryProbeIdentityMonitor = null;
        temporaryProbeResponders = null;
    }

    private static async Task<int> SendPresenceProbesAsync(
        Action<IPAddress, byte[]> sendProbe,
        AdapterProfile activeProfile,
        IReadOnlyList<IPAddress> targets,
        CancellationToken cancellationToken,
        TimeSpan? requestSpacing = null,
        Action<int, int>? progress = null)
    {
        var sent = 0;
        var spacing = requestSpacing ?? DeviceProbePolicy.RequestSpacing;
        foreach (var address in targets)
        {
            cancellationToken.ThrowIfCancellationRequested();
            sendProbe(
                address,
                EthernetFrameCodec.BuildArpRequest(
                    activeProfile.LocalMac,
                    activeProfile.LocalAddress,
                    address));
            sent++;
            if (progress is not null && (sent % 20 == 0 || sent == targets.Count))
            {
                progress(sent, targets.Count);
            }

            await Task.Delay(spacing, cancellationToken);
        }

        if (sent > 0)
        {
            await Task.Delay(DeviceProbePolicy.ReplyWindow, cancellationToken);
        }

        return sent;
    }

    private void OnTemporaryPresencePacketArrival(object sender, PacketCapture capture)
    {
        var activeProfile = temporaryProbeProfile;
        var targets = temporaryProbeTargets;
        var monitor = temporaryProbeIdentityMonitor;
        if (activeProfile is null ||
            targets is null ||
            monitor is null ||
            !EthernetFrameCodec.TryParseArp(capture.Data, out var arp) ||
            arp.Operation != ArpOperation.Reply ||
            !arp.HasConsistentSender ||
            !arp.TargetIp.Equals(activeProfile.LocalAddress) ||
            !targets.Contains(arp.SenderIp) ||
            IsZeroOrBroadcast(arp.SenderMac))
        {
            return;
        }

        var observedAt = DateTimeOffset.UtcNow;
        var identity = monitor.Observe(
            arp,
            activeProfile.LocalAddress,
            activeProfile.LocalMac,
            observedAt);
        if (identity.Warning is not null)
        {
            IdentityAlertDetected?.Invoke(this, identity.Warning);
        }

        if (!identity.IsConflict)
        {
            temporaryProbeResponders?.TryAdd(arp.SenderIp, 0);
            registry.Observe(
                arp.SenderIp,
                arp.SenderMac,
                observedAt,
                GetKnownHostName(arp.SenderMac));
        }
    }

    public async Task ApplyRuleAsync(string macAddress, TrafficRule rule)
    {
        policy.SetRule(macAddress, rule.Normalize());
        if (framePacer is not null)
        {
            await framePacer.ResetAsync(PhysicalAddress.Parse(
                TrafficPolicy.NormalizeMac(macAddress)));
        }

        if (!controlling)
        {
            return;
        }

        var normalized = TrafficPolicy.NormalizeMac(macAddress);
        var client = clients.FirstOrDefault(pair =>
            TrafficPolicy.NormalizeMac(pair.Value.ToString()) == normalized);
        if (!client.Equals(default(KeyValuePair<IPAddress, PhysicalAddress>)))
        {
            PoisonClient(client);
        }
    }

    public async Task StopAsync()
    {
        await stopSync.WaitAsync();
        try
        {
            if (!IsRunning && profile is null)
            {
                return;
            }

            restoring = true;
            controlling = false;
            engineCancellation?.Cancel();
            await AwaitBackgroundTaskAsync();
            if (framePacer is not null)
            {
                await framePacer.DisposeAsync();
                framePacer = null;
            }

            try
            {
                await RestoreArpAsync();
            }
            catch (Exception exception) when (exception is not OperationCanceledException)
            {
                RaiseStatus($"ARP restoration reported an error: {exception.Message}");
            }

            if (arpDevice is not null)
            {
                try
                {
                    arpDevice.StopCapture();
                }
                catch (InvalidOperationException)
                {
                }

                arpDevice.OnPacketArrival -= OnArpPacketArrival;
                arpDevice.Close();
                arpDevice = null;
            }

            forwardingDevice?.Close();
            forwardingDevice = null;
            injectionDevice?.Close();
            injectionDevice = null;
            if (offloadSession is not null)
            {
                try
                {
                    await offloadSession.DisposeAsync();
                }
                catch (Exception exception)
                {
                    RaiseStatus($"Adapter offload restoration reported an error: {exception.Message}");
                }

                offloadSession = null;
            }
            if (ipForwardingSession is not null)
            {
                try
                {
                    await ipForwardingSession.DisposeAsync();
                }
                catch (Exception exception)
                {
                    RaiseStatus(
                        $"Kernel IPv4 forwarding restoration reported an error: {exception.Message}");
                }

                ipForwardingSession = null;
            }
            engineCancellation?.Dispose();
            engineCancellation = null;
            backgroundTask = null;
            frameRouter = null;
            gatewayMac = null;
            profile = null;
            restoring = false;
            var failure = backgroundFailure;
            backgroundFailure = null;
            var stoppedMessage = failure is null
                ? "Stopped. Corrective ARP mappings were sent."
                : $"Stopped after an engine error: {failure}. Corrective ARP mappings were sent.";
            RaiseStatus(stoppedMessage);
            RaiseStateChanged(false, stoppedMessage, failure);
        }
        finally
        {
            stopSync.Release();
        }
    }

    public async ValueTask DisposeAsync()
    {
        await StopAsync();
        GC.SuppressFinalize(this);
    }
    private int ImportCachedNeighbors(
        AdapterProfile activeProfile,
        IReadOnlyList<LinuxArpCacheEntry> cached)
    {
        var imported = 0;
        foreach (var entry in cached)
        {
            if (entry.Address.Equals(activeProfile.GatewayAddress))
            {
                registry.Remember(
                    entry.Address,
                    entry.MacAddress,
                    DateTimeOffset.MinValue,
                    "Gateway");
                continue;
            }

            if (entry.MacAddress.Equals(activeProfile.LocalMac))
            {
                var observation = identityMonitor.Observe(
                    new ArpFrameInfo(
                        ArpOperation.Reply,
                        activeProfile.LocalMac,
                        activeProfile.LocalMac,
                        entry.Address,
                        PhysicalAddress.None,
                        activeProfile.LocalAddress),
                    activeProfile.LocalAddress,
                    activeProfile.LocalMac,
                    DateTimeOffset.UtcNow);
                if (observation.Warning is not null)
                {
                    IdentityAlertDetected?.Invoke(this, observation.Warning);
                }

                continue;
            }

            // Neighbor cache records can be stale. Keep them as offline inventory
            // only; do not turn a cache entry into a forwarding/interception target.
            registry.Remember(
                entry.Address,
                entry.MacAddress,
                DateTimeOffset.MinValue,
                GetKnownHostName(entry.MacAddress));
            imported++;
        }

        return imported;
    }

    private void OnArpPacketArrival(object sender, PacketCapture capture)
    {
        if (EthernetFrameCodec.TryParseArp(capture.Data, out var arp))
        {
            ObserveArp(arp);
            return;
        }

        if (DhcpHostNameParser.TryParse(capture.Data, out var host))
        {
            ObserveHostName(host);
        }
    }

    private void ObserveArp(ArpFrameInfo arp)
    {
        var activeProfile = profile;
        if (activeProfile is null)
        {
            return;
        }

        var identity = identityMonitor.Observe(
            arp,
            activeProfile.LocalAddress,
            activeProfile.LocalMac,
            DateTimeOffset.UtcNow);
        if (identity.Warning is not null)
        {
            IdentityAlertDetected?.Invoke(this, identity.Warning);
        }

        if (identity.IsConflict ||
            !arp.HasConsistentSender ||
            arp.SenderIp.Equals(IPAddress.Any) ||
            arp.SenderIp.Equals(activeProfile.LocalAddress) ||
            arp.SenderMac.Equals(activeProfile.LocalMac) ||
            IsZeroOrBroadcast(arp.SenderMac))
        {
            return;
        }

        if (arp.Operation == ArpOperation.Reply &&
            arp.TargetIp.Equals(activeProfile.LocalAddress) &&
            temporaryProbeTargets?.Contains(arp.SenderIp) == true)
        {
            temporaryProbeResponders?.TryAdd(arp.SenderIp, 0);
        }

        if (arp.SenderIp.Equals(activeProfile.GatewayAddress))
        {
            gatewayResolution?.TrySetResult(arp.SenderMac);
            RespondToArpRequest(arp);
            return;
        }

        var changed = clientMappings.Upsert(arp.SenderIp, arp.SenderMac);
        frameRouter?.UpdateClient(arp.SenderIp, arp.SenderMac);
        registry.Observe(
            arp.SenderIp,
            arp.SenderMac,
            DateTimeOffset.UtcNow,
            GetKnownHostName(arp.SenderMac));
        _ = ResolveNameAsync(arp.SenderIp, arp.SenderMac);
        RespondToArpRequest(arp);
        if (controlling && changed)
        {
            PoisonClient(new KeyValuePair<IPAddress, PhysicalAddress>(
                arp.SenderIp,
                arp.SenderMac));
        }
    }

    private void RunForwardingLoop(
        CancellationToken cancellationToken,
        TaskCompletionSource started)
    {
        try
        {
            var activeDevice = forwardingDevice ??
                throw new InvalidOperationException("The forwarding adapter is not open.");
            started.TrySetResult();
            while (!cancellationToken.IsCancellationRequested)
            {
                var status = activeDevice.GetNextPacket(out var capture);
                if (status == GetPacketStatus.ReadTimeout)
                {
                    continue;
                }

                if (status == GetPacketStatus.Error)
                {
                    throw new InvalidOperationException(
                        $"libpcap forwarding stopped: {activeDevice.LastError}");
                }

                if (status == GetPacketStatus.PacketRead)
                {
                    ProcessForwardingFrame(capture.Data);
                }
            }
        }
        catch (Exception exception) when (!cancellationToken.IsCancellationRequested)
        {
            started.TrySetException(exception);
            HandleBackgroundFailure("Forwarding failed", exception);
        }
    }

    private void ProcessForwardingFrame(ReadOnlySpan<byte> bytes)
    {
        if (!controlling || frameRouter is null)
        {
            return;
        }

        // Some Linux AF_PACKET/libpcap combinations surface an injected or
        // bridged Ethernet frame twice in immediate mode. Never forward or
        // meter the second copy; doing so halves TCP goodput while the target
        // device reports roughly twice the useful download rate.
        if (frameDeduplicator.IsDuplicate(bytes))
        {
            Interlocked.Increment(ref suppressedDuplicatePacketCount);
            return;
        }

        if (DhcpHostNameParser.TryParse(bytes, out var host))
        {
            ObserveHostName(host);
        }

        var result = frameRouter.Route(bytes);
        if (result.Direction is { } direction && result.ClientMac is { } clientMac)
        {
            registry.RecordTraffic(clientMac, direction, result.MeteredByteCount);
        }

        if (result.Direction == TrafficDirection.Upload &&
            result.ClientMac is { } domainClient &&
            result.Observation is { } observation)
        {
            DeviceDomainObserved?.Invoke(
                this,
                new DeviceDomainObservedEventArgs(
                    domainClient,
                    observation,
                    DateTimeOffset.UtcNow,
                    result.BlockedByDomain));
        }

        if (result.Action == FrameAction.Forward &&
            result.Frame is not null &&
            result.Direction is { } forwardingDirection &&
            result.ClientMac is { } forwardingClient)
        {
            var rule = policy.GetRule(forwardingClient.ToString());
            if (!LinuxForwardingStrategy.RequiresPacing(rule, forwardingDirection))
            {
                // Unlimited packets must not cross an extra channel and worker
                // boundary. Sending them immediately from the capture loop keeps
                // Linux forwarding latency comparable to Npcap on Windows while
                // limited traffic still uses the paced per-device queues below.
                SendForwardingPacket(result.Frame);
                Interlocked.Increment(ref forwardedPacketCount);
            }
            else if (framePacer?.TryEnqueue(
                         forwardingClient,
                         forwardingDirection,
                         result.Frame) != true)
            {
                Interlocked.Increment(ref droppedPacketCount);
            }
        }
        else if (result.Action == FrameAction.Drop)
        {
            Interlocked.Increment(ref droppedPacketCount);
        }
    }

    private async Task ResolveNameAsync(IPAddress address, PhysicalAddress mac)
    {
        var key = TrafficPolicy.NormalizeMac(mac.ToString());
        if (!resolvingNames.TryAdd(key, 0))
        {
            return;
        }

        try
        {
            var netBiosTask = NetBiosNameResolver.ResolveAsync(address);
            var mdnsTask = MdnsNameResolver.ResolveAsync(address);
            var dnsTask = ResolveDnsNameAsync(address);
            await Task.WhenAll(netBiosTask, mdnsTask, dnsTask);
            foreach (var name in new[] { netBiosTask.Result, mdnsTask.Result, dnsTask.Result })
            {
                if (resolvedNameClaims.TryClaim(
                        mac,
                        name,
                        out var acceptedName,
                        out var isNewClaim))
                {
                    registry.SetHostName(mac, acceptedName);
                    if (isNewClaim)
                    {
                        DeviceIdentityLearned?.Invoke(
                            this,
                            new DeviceIdentityLearnedEventArgs(mac, acceptedName));
                    }

                    return;
                }
            }
        }
        finally
        {
            resolvingNames.TryRemove(key, out _);
        }
    }

    private void ObserveHostName(DhcpHostNameInfo host)
    {
        var key = TrafficPolicy.NormalizeMac(host.MacAddress.ToString());
        registry.SetHostName(host.MacAddress, host.HostName);
        if (learnedHostNames.TryGetValue(key, out var previous) &&
            string.Equals(previous, host.HostName, StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        learnedHostNames[key] = host.HostName;
        DeviceIdentityLearned?.Invoke(
            this,
            new DeviceIdentityLearnedEventArgs(host.MacAddress, host.HostName));
    }

    private static async Task<string?> ResolveDnsNameAsync(IPAddress address)
    {
        try
        {
            var entry = await Dns.GetHostEntryAsync(address).WaitAsync(TimeSpan.FromSeconds(2));
            var name = entry.HostName.Split('.')[0].Trim();
            return name.Length == 0 || IPAddress.TryParse(name, out _) ? null : name;
        }
        catch (Exception exception) when (
            exception is System.Net.Sockets.SocketException or TimeoutException)
        {
            return null;
        }
    }

    private string? GetKnownHostName(PhysicalAddress mac)
    {
        var key = TrafficPolicy.NormalizeMac(mac.ToString());
        return knownDeviceHints.FirstOrDefault(hint =>
            TrafficPolicy.NormalizeMac(hint.MacAddress.ToString()) == key)?.HostName;
    }

    private async Task RunMaintenanceAsync(CancellationToken cancellationToken)
    {
        using var poisonTimer = new PeriodicTimer(TimeSpan.FromSeconds(5));
        await Task.WhenAll(
            RunTimerAsync(poisonTimer, PoisonClients, cancellationToken),
            RunPresenceProbeLoopAsync(cancellationToken));
    }

    private async Task RunPresenceProbeLoopAsync(CancellationToken cancellationToken)
    {
        using var probeTimer = new PeriodicTimer(DeviceProbePolicy.ProbeInterval);
        while (await probeTimer.WaitForNextTickAsync(cancellationToken))
        {
            var activeProfile = profile;
            if (activeProfile is null || !controlling || restoring)
            {
                continue;
            }

            await refreshSync.WaitAsync(cancellationToken);
            try
            {
                await ProbeAddressesAsync(
                    activeProfile,
                    force: false,
                    cancellationToken);
            }
            catch (Exception exception) when (exception is not OperationCanceledException)
            {
                RaiseStatus($"Device presence check failed: {exception.Message}");
            }
            finally
            {
                refreshSync.Release();
            }
        }
    }

    private static async Task RunTimerAsync(
        PeriodicTimer timer,
        Action action,
        CancellationToken cancellationToken)
    {
        while (await timer.WaitForNextTickAsync(cancellationToken))
        {
            action();
        }
    }
    private void PoisonClients()
    {
        if (!controlling || restoring)
        {
            return;
        }

        foreach (var client in clients)
        {
            PoisonClient(client);
        }
    }

    private void PoisonClient(KeyValuePair<IPAddress, PhysicalAddress> client)
    {
        var activeProfile = profile;
        var activeGateway = gatewayMac;
        if (!controlling || restoring || activeProfile is null || activeGateway is null)
        {
            return;
        }

        var frames = ArpInterceptionFrames.BuildPoison(
            activeProfile.LocalMac,
            activeProfile.GatewayAddress,
            activeGateway,
            client.Key,
            client.Value);
        foreach (var frame in frames.Select(policy.GetInterceptionTargets(client.Value.ToString())))
        {
            SendArpPacket(frame);
        }

    }

    private void RespondToArpRequest(ArpFrameInfo request)
    {
        var activeProfile = profile;
        var activeGateway = gatewayMac;
        if (!controlling || restoring || request.Operation != ArpOperation.Request ||
            activeProfile is null || activeGateway is null)
        {
            return;
        }

        if (request.TargetIp.Equals(activeProfile.GatewayAddress) &&
            clients.TryGetValue(request.SenderIp, out var clientMac) &&
            policy.GetInterceptionTargets(clientMac.ToString())
                .HasFlag(InterceptionTargets.Client))
        {
            SendArpPacket(ArpInterceptionFrames.BuildPoison(
                activeProfile.LocalMac,
                activeProfile.GatewayAddress,
                activeGateway,
                request.SenderIp,
                clientMac).ToClient);
        }
        else if (request.SenderIp.Equals(activeProfile.GatewayAddress) &&
                 clients.TryGetValue(request.TargetIp, out var requestedMac) &&
                 policy.GetInterceptionTargets(requestedMac.ToString())
                    .HasFlag(InterceptionTargets.Gateway))
        {
            SendArpPacket(ArpInterceptionFrames.BuildPoison(
                activeProfile.LocalMac,
                activeProfile.GatewayAddress,
                activeGateway,
                request.TargetIp,
                requestedMac).ToGateway);
        }
    }

    private async Task RestoreArpAsync()
    {
        var activeProfile = profile;
        var activeGateway = gatewayMac;
        if (activeProfile is null || activeGateway is null || injectionDevice is null)
        {
            return;
        }

        for (var attempt = 0; attempt < 3; attempt++)
        {
            foreach (var client in clients)
            {
                SendRestoreFrames(client, activeProfile, activeGateway);
            }

            await Task.Delay(120);
        }
    }

    private void SendRestoreFrames(
        KeyValuePair<IPAddress, PhysicalAddress> client,
        AdapterProfile activeProfile,
        PhysicalAddress activeGateway)
    {
        var restore = ArpInterceptionFrames.BuildRestore(
            activeProfile.LocalMac,
            activeProfile.GatewayAddress,
            activeGateway,
            client.Key,
            client.Value);
        SendArpPacket(restore.ToClient);
        SendArpPacket(restore.ToGateway);
        SendArpPacket(ArpInterceptionFrames.BuildRecoveryRequest(
            activeProfile.LocalMac,
            activeGateway,
            activeProfile.GatewayAddress,
            client.Value,
            client.Key));
        SendArpPacket(EthernetFrameCodec.BuildUnicastArpRequest(
            client.Value,
            client.Key,
            activeGateway,
            activeProfile.GatewayAddress));
    }

    private async Task AwaitBackgroundTaskAsync()
    {
        if (backgroundTask is null)
        {
            return;
        }

        try
        {
            await backgroundTask;
        }
        catch (OperationCanceledException)
        {
        }
        catch (Exception exception)
        {
            RaiseStatus($"Forwarding stopped unexpectedly: {exception.Message}");
        }
    }

    private void SendArpPacket(byte[] bytes)
    {
        SendPacket(bytes);
    }

    private void SendForwardingPacket(byte[] bytes)
    {
        SendPacket(bytes);
    }

    private void SendPacket(byte[] bytes)
    {
        var active = injectionDevice ??
            throw new InvalidOperationException("The packet injection adapter is not open.");
        lock (injectionSync)
        {
            active.SendPacket(bytes);
        }
    }

    private static bool IsZeroOrBroadcast(PhysicalAddress address)
    {
        var bytes = address.GetAddressBytes();
        return bytes.All(value => value == 0) || bytes.All(value => value == 0xff);
    }

    private void HandleBackgroundFailure(string source, Exception exception)
    {
        var failure = $"{source}: {exception.Message}";
        Interlocked.CompareExchange(ref backgroundFailure, failure, null);
        RaiseStatus($"{failure}; restoring the network.");
        engineCancellation?.Cancel();
        _ = Task.Run(StopAsync);
    }

    private void RaiseStatus(string message) => StatusChanged?.Invoke(this, message);

    private void RaiseStateChanged(
        bool isRunning,
        string statusMessage,
        string? failureMessage = null) =>
        StateChanged?.Invoke(
            this,
            new LinuxEngineStateChangedEventArgs(
                isRunning,
                statusMessage,
                failureMessage));
}
