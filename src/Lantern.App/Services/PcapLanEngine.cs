using System.Collections.Concurrent;
using System.Net;
using System.Net.NetworkInformation;
using Lantern.Core.Control;
using Lantern.Core.Devices;
using Lantern.Core.Networking;
using SharpPcap;
using SharpPcap.LibPcap;

namespace Lantern.App.Services;

public sealed class PcapLanEngine : IAsyncDisposable
{
    private readonly object arpSendSync = new();
    private readonly SemaphoreSlim refreshSync = new(1, 1);
    private readonly SemaphoreSlim stopSync = new(1, 1);
    private readonly TrafficPolicy policy;
    private readonly DeviceRegistry registry;
    private readonly ClientMappingCache clientMappings = new();
    private readonly ArpIdentityMonitor identityMonitor = new();
    private readonly ConcurrentDictionary<IPAddress, DateTimeOffset> lastPresenceProbeAt = new();
    private DateTimeOffset lastPresenceProbeBatchAt = DateTimeOffset.MinValue;
    private DateTimeOffset lastDiscoveryProbeBatchAt = DateTimeOffset.MinValue;
    private string? presenceProbeAdapterId;
    private readonly ResolvedDeviceNameClaims resolvedNameClaims = new(Dns.GetHostName());
    private readonly ConcurrentDictionary<string, byte> resolvingNames =
        new(StringComparer.OrdinalIgnoreCase);
    private CancellationTokenSource? engineCancellation;
    private Task? backgroundTask;
    private LibPcapLiveDevice? arpDevice;
    private LibPcapLiveDevice? forwardingDevice;
    private AdapterProfile? profile;
    private PhysicalAddress? gatewayMac;
    private FrameRouter? frameRouter;
    private TaskCompletionSource<PhysicalAddress>? gatewayResolution;
    private KnownDeviceHint[] knownDeviceHints = [];
    private AdapterProfile? temporaryProbeProfile;
    private HashSet<IPAddress>? temporaryProbeTargets;
    private ConcurrentDictionary<IPAddress, byte>? temporaryProbeResponders;
    private ArpIdentityMonitor? temporaryProbeIdentityMonitor;
    private string[] rejectedResolvedNames = [];
    private string? backgroundFailure;
    private volatile bool controlling;
    private volatile bool restoring;
    private long forwardedPacketCount;
    private long droppedPacketCount;

    public PcapLanEngine(DeviceRegistry registry, TrafficPolicy policy)
    {
        this.registry = registry;
        this.policy = policy;
    }

    public bool IsRunning => arpDevice is not null || forwardingDevice is not null;

    public bool IsControlling => controlling;

    public long ForwardedPacketCount => Interlocked.Read(ref forwardedPacketCount);

    public long DroppedPacketCount => Interlocked.Read(ref droppedPacketCount);

    public string DriverName { get; private set; } = "Not started";

    public event EventHandler<string>? StatusChanged;

    public event EventHandler<PcapEngineStateChangedEventArgs>? StateChanged;

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

        await NpfDriverService.EnsureAvailableAsync(cancellationToken);
        profile = adapter;
        clientMappings.BeginAdapter(adapter.Id);
        resolvedNameClaims.Reset(rejectedResolvedNames);
        resolvingNames.Clear();
        registry.BeginSession();
        identityMonitor.Reset();
        SeedRememberedInventory();

        var clients = clientMappings.Mappings;
        restoring = false;
        backgroundFailure = null;
        Interlocked.Exchange(ref forwardedPacketCount, 0);
        Interlocked.Exchange(ref droppedPacketCount, 0);
        gatewayResolution = new TaskCompletionSource<PhysicalAddress>(
            TaskCreationOptions.RunContinuationsAsynchronously);

        var captureDevice = LibPcapLiveDeviceList.Instance
            .FirstOrDefault(candidate => candidate.MacAddress?.Equals(adapter.LocalMac) == true)
            ?? throw new InvalidOperationException(
                $"WinPcap could not match the Windows adapter “{adapter.Name}”.");

        try
        {
            arpDevice = captureDevice;
            arpDevice.OnPacketArrival += OnArpPacketArrival;
            arpDevice.Open(PcapCaptureConfiguration.CreateForArpDiscovery());
            arpDevice.Filter = "arp";
            arpDevice.StartCapture();

            forwardingDevice = new LibPcapLiveDevice(
                captureDevice.Interface ??
                throw new InvalidOperationException("The capture adapter has no interface."));
            forwardingDevice.Open(PcapCaptureConfiguration.CreateForForwarding());
            forwardingDevice.Filter = "ip";
            DriverName = captureDevice.Description ?? captureDevice.Name;
            RaiseStatus($"Resolving gateway {adapter.GatewayAddress}…");

            SendArpPacket(
                EthernetFrameCodec.BuildArpRequest(
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
                policy);

            RaiseStatus("Loading devices already observed by Windows…");
            engineCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            controlling = true;
            var forwarderStarted = new TaskCompletionSource(
                TaskCreationOptions.RunContinuationsAsynchronously);
            var forwardingTask = Task.Run(
                () => RunForwardingLoop(engineCancellation.Token, forwarderStarted));
            backgroundTask = forwardingTask;
            await forwarderStarted.Task.WaitAsync(
                TimeSpan.FromSeconds(2),
                cancellationToken);

            await RefreshNeighborsAsync(engineCancellation.Token);

            PoisonClients();
            backgroundTask = Task.WhenAll(
                forwardingTask,
                RunMaintenanceAsync(engineCancellation.Token));
            const string activeMessage =
                "Live monitoring active — 0 KB/s is unlimited and remains visible.";
            RaiseStatus(activeMessage);
            RaiseStateChanged(true, activeMessage);
        }
        catch (Exception exception)
        {
            var forwardingFailure = backgroundFailure;
            Interlocked.CompareExchange(
                ref backgroundFailure,
                $"Startup failed: {exception.Message}",
                null);
            await StopAsync();
            if (forwardingFailure is not null)
            {
                throw new InvalidOperationException(forwardingFailure, exception);
            }

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
            var cachedEntries = await RefreshWindowsNeighborCacheAsync(
                selectedAdapter,
                cancellationToken);
            var probesSent = 0;
            var devicesResponded = 0;
            var retryRequestsSent = 0;
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
            }
            catch (Exception exception) when (
                !IsRunning && exception is not OperationCanceledException)
            {
                probeWarning = exception.Message;
            }

            return new DiscoveryRefreshResult(
                cachedEntries,
                registry.Peek().Count,
                probesSent,
                probeWarning,
                devicesResponded,
                retryRequestsSent);
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

    private async Task<int> RefreshWindowsNeighborCacheAsync(
        AdapterProfile activeProfile,
        CancellationToken cancellationToken)
    {
        var neighbors = await WindowsNeighborCache.ReadAsync(
            activeProfile,
            cancellationToken);
        var imported = 0;
        foreach (var neighbor in neighbors)
        {
            if (neighbor.Address.Equals(activeProfile.GatewayAddress))
            {
                registry.Remember(
                    neighbor.Address,
                    neighbor.MacAddress,
                    DateTimeOffset.MinValue,
                    "Gateway");
                continue;
            }

            if (neighbor.MacAddress.Equals(activeProfile.LocalMac))
            {
                var observation = identityMonitor.Observe(
                    new ArpFrameInfo(
                        ArpOperation.Reply,
                        activeProfile.LocalMac,
                        activeProfile.LocalMac,
                        neighbor.Address,
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

            // A neighbor-cache entry is historical evidence, not proof that the
            // device is currently reachable. Keep it in inventory only; do not
            // add it to the forwarding/interception client map.
            registry.Remember(
                neighbor.Address,
                neighbor.MacAddress,
                DateTimeOffset.MinValue,
                GetKnownHostName(neighbor.MacAddress));
            imported++;
        }

        return imported;
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
                responders.Count);
        }

        if (arpDevice is not null)
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

        await NpfDriverService.EnsureAvailableAsync(cancellationToken);
        var captureDevice = LibPcapLiveDeviceList.Instance
            .FirstOrDefault(candidate => candidate.MacAddress?.Equals(activeProfile.LocalMac) == true)
            ?? throw new InvalidOperationException(
                $"Npcap could not find adapter “{activeProfile.Name}” for device presence checks.");

        BeginTemporaryProbeContext(activeProfile, targets, responders, createIdentityMonitor: true);
        captureDevice.OnPacketArrival += OnTemporaryPresencePacketArrival;
        var captureOpened = false;
        var captureStarted = false;
        try
        {
            captureDevice.Open(PcapCaptureConfiguration.CreateForArpDiscovery());
            captureOpened = true;
            captureDevice.Filter = "arp";
            captureDevice.StartCapture();
            captureStarted = true;

            return await SendBatchesAsync(
                (address, bytes) =>
                {
                    lock (arpSendSync)
                    {
                        captureDevice.SendPacket(bytes);
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
            try
            {
                await ForwardingShutdown.RunAsync(
                    () => arpDevice is null ? Task.CompletedTask : RestoreArpAsync(),
                    () =>
                    {
                        controlling = false;
                        engineCancellation?.Cancel();
                    },
                    AwaitBackgroundTaskAsync);
            }
            catch (Exception exception) when (exception is not OperationCanceledException)
            {
                RaiseStatus(
                    $"Network restoration reported an error; closing safely: {exception.Message}");
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

            if (forwardingDevice is not null)
            {
                forwardingDevice.Close();
                forwardingDevice = null;
            }

            engineCancellation?.Dispose();
            engineCancellation = null;
            backgroundTask = null;
            frameRouter = null;
            gatewayMac = null;
            profile = null;
            restoring = false;
            var failure = backgroundFailure;
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

    public async Task ApplyRuleAsync(string macAddress, TrafficRule rule)
    {
        var clients = clientMappings.Mappings;
        var previousTargets = policy.GetInterceptionTargets(macAddress);
        policy.SetRule(macAddress, rule.Normalize());
        var currentTargets = policy.GetInterceptionTargets(macAddress);
        if (controlling)
        {
            var normalizedMac = TrafficPolicy.NormalizeMac(macAddress);
            foreach (var client in clients)
            {
                if (string.Equals(
                        TrafficPolicy.NormalizeMac(client.Value.ToString()),
                        normalizedMac,
                        StringComparison.Ordinal))
                {
                    await ApplyInterceptionTransitionAsync(
                        client,
                        InterceptionTransition.Between(previousTargets, currentTargets));
                    break;
                }
            }
        }
    }

    public async ValueTask DisposeAsync()
    {
        await StopAsync();
        GC.SuppressFinalize(this);
    }

    private void OnArpPacketArrival(object sender, PacketCapture capture)
    {
        if (EthernetFrameCodec.TryParseArp(capture.Data, out var arp))
        {
            ObserveArp(arp);
        }
    }

    private void RunForwardingLoop(
        CancellationToken cancellationToken,
        TaskCompletionSource forwarderStarted)
    {
        try
        {
            var activeDevice = forwardingDevice ??
                throw new InvalidOperationException("The forwarding adapter is not open.");
            var startupReported = false;
            while (!cancellationToken.IsCancellationRequested)
            {
                var status = activeDevice.GetNextPacket(out var capture);
                if (!startupReported)
                {
                    ForwarderStartupPolicy.ObserveFirstRead(
                        forwarderStarted,
                        status,
                        activeDevice.LastError);
                    startupReported = true;
                }

                if (status == GetPacketStatus.ReadTimeout)
                {
                    continue;
                }

                if (status == GetPacketStatus.Error)
                {
                    throw new InvalidOperationException(
                        $"Packet forwarding stopped: {activeDevice.LastError}");
                }

                if (status != GetPacketStatus.PacketRead)
                {
                    continue;
                }

                ProcessForwardingFrame(capture.Data);
            }
        }
        catch (Exception exception) when (!cancellationToken.IsCancellationRequested)
        {
            forwarderStarted.TrySetException(exception);
            HandleBackgroundFailure("Forwarding failed", exception);
        }
    }

    private void ProcessForwardingFrame(ReadOnlySpan<byte> bytes)
    {
        if (!controlling || frameRouter is null)
        {
            return;
        }

        if (DhcpHostNameParser.TryParse(bytes, out var dhcpHost))
        {
            registry.SetHostName(dhcpHost.MacAddress, dhcpHost.HostName);
            DeviceIdentityLearned?.Invoke(
                this,
                new DeviceIdentityLearnedEventArgs(
                    dhcpHost.MacAddress,
                    dhcpHost.HostName));
        }

        var result = frameRouter.Route(bytes);
        if (result.Direction is not null && result.ClientMac is not null)
        {
            registry.RecordTraffic(
                result.ClientMac,
                result.Direction.Value,
                result.MeteredByteCount);
        }

        if (result.Direction == TrafficDirection.Upload &&
            result.ClientMac is not null &&
            result.Observation is { } observation)
        {
            DeviceDomainObserved?.Invoke(
                this,
                new DeviceDomainObservedEventArgs(
                    result.ClientMac,
                    observation,
                    DateTimeOffset.UtcNow,
                    result.BlockedByDomain));
        }

        if (result.Action == FrameAction.Forward && result.Frame is not null)
        {
            SendForwardingPacket(result.Frame);
            Interlocked.Increment(ref forwardedPacketCount);
        }
        else if (result.Action == FrameAction.Drop)
        {
            Interlocked.Increment(ref droppedPacketCount);
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

        var needsPoison = clientMappings.Upsert(arp.SenderIp, arp.SenderMac);
        frameRouter?.UpdateClient(arp.SenderIp, arp.SenderMac);
        registry.Observe(
            arp.SenderIp,
            arp.SenderMac,
            DateTimeOffset.UtcNow,
            GetKnownHostName(arp.SenderMac));
        _ = ResolveNameAsync(arp.SenderIp, arp.SenderMac);
        RespondToArpRequest(arp);
        if (controlling && needsPoison)
        {
            PoisonClient(
                new KeyValuePair<IPAddress, PhysicalAddress>(
                    arp.SenderIp,
                    arp.SenderMac));
        }
    }

    private async Task ResolveNameAsync(IPAddress address, PhysicalAddress mac)
    {
        var key = mac.ToString();
        if (!resolvingNames.TryAdd(key, 0))
        {
            return;
        }

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

    private static async Task<string?> ResolveDnsNameAsync(IPAddress address)
    {
        try
        {
            var entry = await Dns.GetHostEntryAsync(address)
                .WaitAsync(TimeSpan.FromSeconds(2));
            var name = entry.HostName.Split('.')[0].Trim();
            return name.Length == 0 || IPAddress.TryParse(name, out _) ? null : name;
        }
        catch (Exception exception) when (
            exception is System.Net.Sockets.SocketException or TimeoutException)
        {
            return null;
        }
    }

    private string? GetKnownHostName(PhysicalAddress macAddress)
    {
        var key = TrafficPolicy.NormalizeMac(macAddress.ToString());
        return knownDeviceHints.FirstOrDefault(
            hint => string.Equals(
                TrafficPolicy.NormalizeMac(hint.MacAddress.ToString()),
                key,
                StringComparison.OrdinalIgnoreCase))?.HostName;
    }

    private Task RunMaintenanceAsync(CancellationToken cancellationToken) =>
        Task.WhenAll(
            RunPoisonLoopAsync(cancellationToken),
            RunPresenceProbeLoopAsync(cancellationToken));

    private async Task RunPoisonLoopAsync(CancellationToken cancellationToken)
    {
        var poisonTimer = new PeriodicTimer(TimeSpan.FromSeconds(5));
        try
        {
            while (await poisonTimer.WaitForNextTickAsync(cancellationToken))
            {
                PoisonClients();
            }
        }
        finally
        {
            poisonTimer.Dispose();
        }
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

    private void PoisonClients()
    {
        var clients = clientMappings.Mappings;
        var activeProfile = profile;
        var activeGatewayMac = gatewayMac;
        if (!controlling || restoring || activeProfile is null || activeGatewayMac is null)
        {
            return;
        }

        foreach (var pair in clients)
        {
            PoisonClient(pair);
        }
    }

    private async Task RestoreArpAsync()
    {
        var clients = clientMappings.Mappings;
        var activeProfile = profile;
        var activeGatewayMac = gatewayMac;
        if (activeProfile is null || activeGatewayMac is null)
        {
            return;
        }

        for (var attempt = 0; attempt < 3; attempt++)
        {
            foreach (var pair in clients)
            {
                SendRestoreFrames(pair, activeProfile, activeGatewayMac);
            }

            await Task.Delay(120);
        }
    }

    private void PoisonClient(KeyValuePair<IPAddress, PhysicalAddress> client)
    {
        PoisonClient(client, policy.GetInterceptionTargets(client.Value.ToString()));
    }

    private void PoisonClient(
        KeyValuePair<IPAddress, PhysicalAddress> client,
        InterceptionTargets targets)
    {
        var activeProfile = profile;
        var activeGatewayMac = gatewayMac;
        if (!controlling || restoring || targets == InterceptionTargets.None ||
            activeProfile is null || activeGatewayMac is null)
        {
            return;
        }

        var frames = ArpInterceptionFrames.BuildPoison(
            activeProfile.LocalMac,
            activeProfile.GatewayAddress,
            activeGatewayMac,
            client.Key,
            client.Value);
        foreach (var frame in frames.Select(targets))
        {
            SendArpPacket(frame);
        }

        var controllerFrames = ArpInterceptionFrames.BuildControllerProtection(
            activeProfile.LocalMac,
            activeProfile.LocalAddress,
            activeGatewayMac,
            activeProfile.GatewayAddress,
            client.Value,
            client.Key);
        SendArpPacket(controllerFrames.ClientToController);
        SendArpPacket(controllerFrames.GatewayToController);
    }

    private async Task ApplyInterceptionTransitionAsync(
        KeyValuePair<IPAddress, PhysicalAddress> client,
        InterceptionTransition transition)
    {
        var activeProfile = profile;
        var activeGatewayMac = gatewayMac;
        if (!controlling || restoring || activeProfile is null || activeGatewayMac is null)
        {
            return;
        }

        if (transition.Restore == InterceptionTargets.None)
        {
            PoisonClient(client);
            return;
        }

        for (var attempt = 0; attempt < 3; attempt++)
        {
            if (!controlling || restoring || arpDevice is null)
            {
                return;
            }

            SendRestoreFrames(client, activeProfile, activeGatewayMac);
            PoisonClient(client);
            if (attempt < 2)
            {
                await Task.Delay(40);
            }
        }
    }

    private void SendRestoreFrames(
        KeyValuePair<IPAddress, PhysicalAddress> client,
        AdapterProfile activeProfile,
        PhysicalAddress activeGatewayMac)
    {
        var restoreFrames = ArpInterceptionFrames.BuildRestore(
            activeProfile.LocalMac,
            activeProfile.GatewayAddress,
            activeGatewayMac,
            client.Key,
            client.Value);
        SendArpPacket(restoreFrames.ToClient);
        SendArpPacket(restoreFrames.ToGateway);

        // Also ask a connected client to answer the gateway itself. The direct
        // replies above cover clients that disconnected before restoration.
        var recoveryRequest = ArpInterceptionFrames.BuildRecoveryRequest(
            activeProfile.LocalMac,
            activeGatewayMac,
            activeProfile.GatewayAddress,
            client.Value,
            client.Key);
        SendArpPacket(recoveryRequest);
    }

    private void RespondToArpRequest(ArpFrameInfo request)
    {
        var clients = clientMappings.Mappings;
        var activeProfile = profile;
        var activeGatewayMac = gatewayMac;
        if (!controlling || restoring ||
            request.Operation != ArpOperation.Request ||
            activeProfile is null ||
            activeGatewayMac is null)
        {
            return;
        }

        if (request.TargetIp.Equals(activeProfile.GatewayAddress) &&
            clients.TryGetValue(request.SenderIp, out var requestingClient))
        {
            if (!policy.GetInterceptionTargets(requestingClient.ToString())
                    .HasFlag(InterceptionTargets.Client))
            {
                return;
            }

            var frames = ArpInterceptionFrames.BuildPoison(
                activeProfile.LocalMac,
                activeProfile.GatewayAddress,
                activeGatewayMac,
                request.SenderIp,
                requestingClient);
            SendArpPacket(frames.ToClient);
            return;
        }

        if (request.SenderIp.Equals(activeProfile.GatewayAddress) &&
            clients.TryGetValue(request.TargetIp, out var requestedClient))
        {
            if (!policy.GetInterceptionTargets(requestedClient.ToString())
                    .HasFlag(InterceptionTargets.Gateway))
            {
                return;
            }

            var frames = ArpInterceptionFrames.BuildPoison(
                activeProfile.LocalMac,
                activeProfile.GatewayAddress,
                activeGatewayMac,
                request.TargetIp,
                requestedClient);
            SendArpPacket(frames.ToGateway);
        }
    }

    private void SendArpPacket(byte[] bytes)
    {
        var activeDevice = arpDevice ??
            throw new InvalidOperationException("The ARP capture adapter is not open.");
        lock (arpSendSync)
        {
            activeDevice.SendPacket(bytes);
        }
    }

    private void SendForwardingPacket(byte[] bytes)
    {
        // Some Wi-Fi drivers allow a second Npcap handle to capture but reject
        // packet injection through it with ERROR_BAD_UNIT (20). The ARP handle
        // has already proven that it can inject on this adapter, and capture
        // filters do not restrict packets sent through a handle.
        var activeDevice = PacketInjectionPolicy.SelectHandle(arpDevice, forwardingDevice);
        var frames = PacketInjectionPolicy.PrepareFrames(bytes);
        for (var index = 0; index < frames.Count; index++)
        {
            var frame = frames[index];
            try
            {
                lock (arpSendSync)
                {
                    activeDevice.SendPacket(frame);
                }
            }
            catch (Exception exception)
            {
                var adapterName = profile?.Name ?? "unknown adapter";
                throw new InvalidOperationException(
                    $"Npcap rejected a forwarded frame on '{adapterName}' " +
                    $"(captured {bytes.Length} bytes, sending {frame.Length} bytes, " +
                    $"segment {index + 1}/{frames.Count}): {exception.Message}",
                    exception);
            }
        }
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
            RaiseStatus(
                $"Forwarding stopped unexpectedly; restoring network: {exception.Message}");
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
            new PcapEngineStateChangedEventArgs(
                isRunning,
                statusMessage,
                failureMessage));
}
