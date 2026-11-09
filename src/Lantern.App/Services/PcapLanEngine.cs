using System.Collections.Concurrent;
using System.Diagnostics;
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
    private const long CaptureQueueMaximumBytes = 32 * 1024 * 1024;
    private const long ForwardingQueueMaximumBytes = 32 * 1024 * 1024;
    private const long PriorityQueueMaximumBytes = 1024 * 1024;
    private static readonly TimeSpan CaptureStatisticsInterval = TimeSpan.FromSeconds(2);
    private readonly SemaphoreSlim refreshSync = new(1, 1);
    private readonly SemaphoreSlim lifecycleSync = new(1, 1);
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
    private Task? injectionWorkerTask;
    private BoundedPacketQueue? captureQueue;
    private PriorityPacketInjectionQueue? injectionQueue;
    private PcapRuntimeInfo? pcapRuntimeInfo;
    private string? transientDegradedReason;
    private string? captureStatisticsWarning;
    private uint previousCaptureReceived;
    private uint previousCaptureDropped;
    private bool captureStatisticsInitialized;
    private int engineHealthy;
    private int injectionRetryAttempts;
    private int injectionSendFailures;
    private long captureReceivedPackets;
    private long captureKernelDroppedPackets;
    private long lastCaptureStatisticsTimestamp;
    private long captureBytes;
    private long forwardedBytes;
    private long capturePacketsPerSecondMilli;
    private long captureBytesPerSecond;
    private long forwardedPacketsPerSecondMilli;
    private long forwardedBytesPerSecond;
    private long processCpuMilliPercent;
    private long lastCaptureStatisticsTimestamp;
    private long previousCaptureBytesSample;
    private long previousForwardedPacketsSample;
    private long previousForwardedBytesSample;
    private long previousProcessCpuTicks;
    private long previousProcessCpuTimestamp;
    private long lastArpQueueLatencyTicks;
    private long lastForwardingQueueLatencyTicks;
    private long captureQueueDroppedPackets;
    private long injectionQueueDroppedPackets;
    private long lastCaptureUtcTicks;
    private long lastArpInjectionUtcTicks;
    private long lastForwardedInjectionUtcTicks;
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

    public bool IsHealthy =>
        IsRunning &&
        arpDevice?.Opened == true &&
        forwardingDevice?.Opened == true &&
        Volatile.Read(ref engineHealthy) == 1 &&
        backgroundFailure is null &&
        Volatile.Read(ref transientDegradedReason) is null &&
        Volatile.Read(ref captureStatisticsWarning) is null &&
        pcapRuntimeInfo?.NativeLibraryPath is not null &&
        backgroundTask?.IsCompleted != true;

    public bool IsControlling => controlling;

    public PcapEngineHealthSnapshot GetHealthSnapshot()
    {
        var runtime = pcapRuntimeInfo;
        var currentCaptureQueue = captureQueue;
        var currentInjectionQueue = injectionQueue;
        return new PcapEngineHealthSnapshot(
            IsRunning,
            IsHealthy,
            backgroundFailure ?? Volatile.Read(ref transientDegradedReason),
            runtime?.CaptureLibraryVersion ?? "Not loaded",
            runtime?.SharpPcapVersion ?? "Unknown",
            runtime?.NativeLibraryPath,
            runtime?.NativeLibraryFileVersion,
            Interlocked.Read(ref captureReceivedPackets),
            Interlocked.Read(ref captureKernelDroppedPackets),
            Interlocked.Read(ref captureQueueDroppedPackets),
            Interlocked.Read(ref injectionQueueDroppedPackets),
            ForwardedPacketCount,
            DroppedPacketCount,
            Volatile.Read(ref injectionSendFailures),
            Volatile.Read(ref injectionRetryAttempts),
            currentCaptureQueue?.BufferedBytes ?? 0,
            currentInjectionQueue?.ForwardingQueueBytes ?? 0,
            currentInjectionQueue?.PriorityQueueBytes ?? 0,
            Interlocked.Read(ref capturePacketsPerSecondMilli) / 1000d,
            Interlocked.Read(ref captureBytesPerSecond),
            Interlocked.Read(ref forwardedPacketsPerSecondMilli) / 1000d,
            Interlocked.Read(ref forwardedBytesPerSecond),
            Interlocked.Read(ref processCpuMilliPercent) / 1000d,
            TimeSpan.FromTicks(Interlocked.Read(ref lastArpQueueLatencyTicks)).TotalMilliseconds,
            TimeSpan.FromTicks(Interlocked.Read(ref lastForwardingQueueLatencyTicks)).TotalMilliseconds,
            ReadTimestamp(Interlocked.Read(ref lastCaptureUtcTicks)),
            ReadTimestamp(Interlocked.Read(ref lastArpInjectionUtcTicks)),
            ReadTimestamp(Interlocked.Read(ref lastForwardedInjectionUtcTicks)),
            Volatile.Read(ref captureStatisticsWarning),
            runtime?.Error);
    }

    private static DateTimeOffset? ReadTimestamp(long utcTicks) =>
        utcTicks <= 0 ? null : new DateTimeOffset(utcTicks, TimeSpan.Zero);

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
        ArgumentNullException.ThrowIfNull(adapter);
        await lifecycleSync.WaitAsync(cancellationToken);
        try
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
            controlling = false;
            backgroundFailure = null;
            transientDegradedReason = null;
            Volatile.Write(ref engineHealthy, 0);
            Interlocked.Exchange(ref forwardedPacketCount, 0);
            Interlocked.Exchange(ref droppedPacketCount, 0);
            Interlocked.Exchange(ref captureReceivedPackets, 0);
            Interlocked.Exchange(ref captureKernelDroppedPackets, 0);
            Interlocked.Exchange(ref captureBytes, 0);
            Interlocked.Exchange(ref forwardedBytes, 0);
            Interlocked.Exchange(ref capturePacketsPerSecondMilli, 0);
            Interlocked.Exchange(ref captureBytesPerSecond, 0);
            Interlocked.Exchange(ref forwardedPacketsPerSecondMilli, 0);
            Interlocked.Exchange(ref forwardedBytesPerSecond, 0);
            Interlocked.Exchange(ref processCpuMilliPercent, 0);
            Interlocked.Exchange(ref lastArpQueueLatencyTicks, 0);
            Interlocked.Exchange(ref lastForwardingQueueLatencyTicks, 0);
            lastCaptureStatisticsTimestamp = 0;
            lastCaptureStatisticsTimestamp = 0;
            previousCaptureBytesSample = 0;
            previousForwardedPacketsSample = 0;
            previousForwardedBytesSample = 0;
            previousProcessCpuTicks = 0;
            previousProcessCpuTimestamp = 0;
            Interlocked.Exchange(ref captureQueueDroppedPackets, 0);
            Interlocked.Exchange(ref injectionQueueDroppedPackets, 0);
            Interlocked.Exchange(ref injectionRetryAttempts, 0);
            Interlocked.Exchange(ref injectionSendFailures, 0);
            Interlocked.Exchange(ref lastCaptureUtcTicks, 0);
            Interlocked.Exchange(ref lastArpInjectionUtcTicks, 0);
            Interlocked.Exchange(ref lastForwardedInjectionUtcTicks, 0);
            captureStatisticsInitialized = false;
            captureStatisticsWarning = null;
            pcapRuntimeInfo = null;
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

                // Force SharpPcap to resolve its native capture library, then record
                // the actual loaded module path instead of inferring it from installation state.
                pcapRuntimeInfo = PcapRuntimeInspector.Inspect();
                if (pcapRuntimeInfo.NativeLibraryPath is null)
                {
                    var warning =
                        $"Capture library loaded as '{pcapRuntimeInfo.CaptureLibraryVersion}', " +
                        $"but its native module path could not be verified: {pcapRuntimeInfo.Error}";
                    SetTransientDegraded(warning);
                    RaiseStatus(warning);
                }
                else
                {
                    RaiseStatus(
                        $"Using {pcapRuntimeInfo.CaptureLibraryVersion}; native module: " +
                        $"{pcapRuntimeInfo.NativeLibraryPath}.");
                }

                RaiseStatus($"Resolving gateway {adapter.GatewayAddress}…");
                await ArpEnforcementRetry.ExecuteAsync(
                    () => SendArpPacketDirect(
                        EthernetFrameCodec.BuildArpRequest(
                            adapter.LocalMac,
                            adapter.LocalAddress,
                            adapter.GatewayAddress)),
                    cancellationToken,
                    OnInjectionRetry);

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
                engineCancellation = new CancellationTokenSource();
                captureQueue = new BoundedPacketQueue(CaptureQueueMaximumBytes);
                var activeInjectionQueue = new PriorityPacketInjectionQueue(
                    ForwardingQueueMaximumBytes,
                    PriorityQueueMaximumBytes);
                injectionQueue = activeInjectionQueue;

                controlling = true;
                var engineToken = engineCancellation.Token;
                var forwarderStarted = new TaskCompletionSource(
                    TaskCreationOptions.RunContinuationsAsynchronously);

                var captureTask = BackgroundLoopSupervisor.RunAsync(
                    "Npcap capture loop",
                    () => Task.Run(() => RunForwardingLoop(engineToken, forwarderStarted)),
                    engineToken,
                    HandleBackgroundFailure);

                var processingTask = BackgroundLoopSupervisor.RunAsync(
                    "Packet processing loop",
                    () => RunPacketProcessingLoopAsync(engineToken),
                    engineToken,
                    HandleBackgroundFailure);

                injectionWorkerTask = activeInjectionQueue.RunAsync(
                    SendInjectionPacket,
                    () => controlling && !restoring,
                    OnInjectionRetry,
                    HandleBackgroundFailure,
                    engineToken);
                var activeInjectionWorkerTask = injectionWorkerTask;
                var injectionTask = BackgroundLoopSupervisor.RunAsync(
                    "Npcap injection loop",
                    () => activeInjectionWorkerTask,
                    engineToken,
                    HandleBackgroundFailure);

                var maintenanceTask = BackgroundLoopSupervisor.RunAsync(
                    "Maintenance loops",
                    () => RunMaintenanceAsync(engineToken),
                    engineToken,
                    HandleBackgroundFailure);

                backgroundTask = Task.WhenAll(
                    captureTask,
                    processingTask,
                    injectionTask,
                    maintenanceTask);

                await forwarderStarted.Task.WaitAsync(
                    TimeSpan.FromSeconds(2),
                    cancellationToken);

                await RefreshNeighborsAsync(cancellationToken);
                if (backgroundFailure is not null)
                {
                    throw new InvalidOperationException(backgroundFailure);
                }

                PoisonClients();
                Volatile.Write(ref engineHealthy, 1);
                if (!IsHealthy)
                {
                    throw new InvalidOperationException(
                        backgroundFailure ??
                        Volatile.Read(ref transientDegradedReason) ??
                        "Packet capture health could not be verified.");
                }

                const string activeMessage =
                    "Live monitoring active — packet capture, queue pressure, Npcap drops, " +
                    "and injection health are being monitored.";
                RaiseStatus(activeMessage);
                RaiseStateChanged(true, activeMessage, isHealthy: IsHealthy);
            }
            catch (Exception exception)
            {
                var failure = backgroundFailure;
                Interlocked.CompareExchange(
                    ref backgroundFailure,
                    $"Startup failed: {exception.Message}",
                    null);
                Volatile.Write(ref engineHealthy, 0);
                controlling = false;
                await StopCoreAsync();
                if (failure is not null)
                {
                    throw new InvalidOperationException(failure, exception);
                }

                throw;
            }
        }
        finally
        {
            lifecycleSync.Release();
        }
    }

    public async Task<DiscoveryRefreshResult> RefreshNeighborsAsync(
        CancellationToken cancellationToken = default)
    {
        var activeProfile = profile ??
            throw new InvalidOperationException("Select an adapter before scanning devices.");
        await refreshSync.WaitAsync(cancellationToken);
        try
        {
            SeedRememberedInventory();
            var cachedEntries = await RefreshWindowsNeighborCacheAsync(
                activeProfile,
                cancellationToken);
            return new DiscoveryRefreshResult(cachedEntries, registry.Peek().Count);
        }
        finally
        {
            refreshSync.Release();
        }
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
                cachedEntries,
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
                responders.Count,
                discoverSubnet ? targets.Count : 0);
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
        await lifecycleSync.WaitAsync();
        try
        {
            await StopCoreAsync();
        }
        finally
        {
            lifecycleSync.Release();
        }
    }

    private async Task StopCoreAsync()
    {
        if (!IsRunning && profile is null && engineCancellation is null)
        {
            return;
        }

        controlling = false;
        Volatile.Write(ref engineHealthy, 0);

        // Let an in-flight presence/discovery probe finish before restoration.
        // Once the semaphore is acquired, no maintenance probe can enqueue ARP
        // frames ahead of corrective mappings.
        await refreshSync.WaitAsync();
        try
        {
            restoring = true;
            try
            {
                await ForwardingShutdown.RunAsync(
                    () => arpDevice is null ? Task.CompletedTask : RestoreArpAsync(),
                    () => engineCancellation?.Cancel(),
                    AwaitBackgroundTaskAsync);
            }
            catch (Exception exception) when (exception is not OperationCanceledException)
            {
                RaiseStatus(
                    $"Network restoration reported an error; closing safely: {exception.Message}");
            }
        }
        finally
        {
            refreshSync.Release();
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
        injectionWorkerTask = null;
        captureQueue = null;
        injectionQueue = null;
        frameRouter = null;
        gatewayMac = null;
        profile = null;
        restoring = false;
        var failure = backgroundFailure;
        var stoppedMessage = failure is null
            ? "Stopped. Corrective ARP mappings were sent."
            : $"Stopped after an engine error: {failure}. Corrective ARP mappings were attempted.";
        RaiseStatus(stoppedMessage);
        RaiseStateChanged(false, stoppedMessage, failure, isHealthy: false);
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
        try
        {
            if (EthernetFrameCodec.TryParseArp(capture.Data, out var arp))
            {
                ObserveArp(arp);
            }
        }
        catch (Exception exception) when (!restoring)
        {
            HandleBackgroundFailure("ARP packet handling failed", exception);
        }
    }

    private void RunForwardingLoop(
        CancellationToken cancellationToken,
        TaskCompletionSource forwarderStarted)
    {
        var activeDevice = forwardingDevice ??
            throw new InvalidOperationException("The forwarding adapter is not open.");
        var activeQueue = captureQueue ??
            throw new InvalidOperationException("The capture processing queue is not available.");
        var startupReported = false;
        var nextStatisticsPoll = Stopwatch.GetTimestamp();

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

            var now = Stopwatch.GetTimestamp();
            if (now >= nextStatisticsPoll)
            {
                PollCaptureStatistics(activeDevice);
                nextStatisticsPoll = now +
                    (long)(CaptureStatisticsInterval.TotalSeconds * Stopwatch.Frequency);
            }

            if (status == GetPacketStatus.ReadTimeout)
            {
                continue;
            }

            if (status == GetPacketStatus.Error)
            {
                throw new InvalidOperationException(
                    $"Packet capture stopped: {activeDevice.LastError}");
            }

            if (status != GetPacketStatus.PacketRead)
            {
                continue;
            }

            Interlocked.Exchange(ref lastCaptureUtcTicks, DateTimeOffset.UtcNow.UtcTicks);
            Interlocked.Add(ref captureBytes, capture.Data.Length);
            if (!controlling || restoring)
            {
                continue;
            }

            if (!activeQueue.TryWrite(capture.Data))
            {
                Interlocked.Increment(ref captureQueueDroppedPackets);
                Interlocked.Increment(ref droppedPacketCount);
                SetTransientDegraded(
                    "Capture processing queue is full; packets are being dropped rather than queued without limit.");
            }
        }
    }

    private async Task RunPacketProcessingLoopAsync(CancellationToken cancellationToken)
    {
        var activeQueue = captureQueue ??
            throw new InvalidOperationException("The capture processing queue is not available.");

        while (true)
        {
            var packet = await activeQueue.ReadAsync(cancellationToken);
            if (controlling && !restoring)
            {
                ProcessForwardingFrame(packet);
            }

            RefreshQueueHealth();
        }
    }

    private void ProcessForwardingFrame(ReadOnlySpan<byte> bytes)
    {
        if (!controlling || restoring || frameRouter is null)
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
            var activeQueue = injectionQueue ??
                throw new InvalidOperationException("The packet injection queue is not available.");
            var frames = PacketInjectionPolicy.PrepareFrames(result.Frame);
            if (!activeQueue.TryEnqueueForwarding(
                    frames,
                    () =>
                    {
                        Interlocked.Increment(ref forwardedPacketCount);
                        Interlocked.Add(
                            ref forwardedBytes,
                            frames.Sum(static frame => (long)frame.Length));
                        Interlocked.Exchange(
                            ref lastForwardedInjectionUtcTicks,
                            DateTimeOffset.UtcNow.UtcTicks);
                    },
                    RecordForwardingQueueLatency))
            {
                Interlocked.Increment(ref injectionQueueDroppedPackets);
                Interlocked.Increment(ref droppedPacketCount);
                SetTransientDegraded(
                    "Forwarding injection queue is full; forwarded packets are being dropped to preserve bounded memory.");
            }
        }
        else if (result.Action == FrameAction.Drop)
        {
            Interlocked.Increment(ref droppedPacketCount);
        }
    }

    private void PollCaptureStatistics(LibPcapLiveDevice activeDevice)
    {
        try
        {
            var statistics = activeDevice.Statistics ??
                throw new InvalidOperationException("Npcap did not return capture statistics.");
            var received = statistics.ReceivedPackets;
            var dropped = statistics.DroppedPackets;
            var firstStatisticsSample = !captureStatisticsInitialized;

            if (firstStatisticsSample)
            {
                Interlocked.Add(ref captureReceivedPackets, received);
                Interlocked.Add(ref captureKernelDroppedPackets, dropped);
                captureStatisticsInitialized = true;
            }
            else
            {
                Interlocked.Add(
                    ref captureReceivedPackets,
                    unchecked((uint)(received - previousCaptureReceived)));
                Interlocked.Add(
                    ref captureKernelDroppedPackets,
                    unchecked((uint)(dropped - previousCaptureDropped)));
            }

            var newlyReceived = firstStatisticsSample
                ? received
                : unchecked((uint)(received - previousCaptureReceived));
            var newlyDropped = firstStatisticsSample
                ? dropped
                : unchecked((uint)(dropped - previousCaptureDropped));
            UpdatePerformanceMetrics(newlyReceived);
            previousCaptureReceived = received;
            previousCaptureDropped = dropped;
            Volatile.Write(ref captureStatisticsWarning, null);
            ClearTransientDegraded("Npcap capture statistics are unavailable");

            if (newlyDropped > 0)
            {
                SetTransientDegraded(
                    $"Npcap reported {newlyDropped} capture-buffer drop(s) in the latest statistics interval.");
            }
            else
            {
                ClearTransientDegraded("Npcap reported");
            }
        }
        catch (Exception exception)
        {
            var warning =
                $"Npcap capture statistics are unavailable: {exception.Message}";
            Volatile.Write(ref captureStatisticsWarning, warning);
            SetTransientDegraded(warning);
            RaiseStatus(warning);
        }
    }

    private void OnInjectionRetry(string operation, int attempt, Exception exception)
    {
        Interlocked.Increment(ref injectionRetryAttempts);
        RaiseStatus(
            $"{operation} packet injection had a transient error; retry {attempt}/" +
            $"{ArpEnforcementRetry.MaxAttempts}: {exception.Message}");
    }

    private void SetTransientDegraded(string reason)
    {
        var previous = Interlocked.CompareExchange(ref transientDegradedReason, reason, null);
        if (previous is not null)
        {
            return;
        }

        Volatile.Write(ref engineHealthy, 0);
        RaiseStatus($"Packet processing health degraded: {reason}");
        RaiseStateChanged(
            IsRunning,
            $"Packet processing health degraded: {reason}",
            isHealthy: false);
    }

    private void ClearTransientDegraded(string expectedPrefix)
    {
        var current = Volatile.Read(ref transientDegradedReason);
        if (current is null ||
            !current.StartsWith(expectedPrefix, StringComparison.Ordinal))
        {
            return;
        }

        if (Interlocked.CompareExchange(ref transientDegradedReason, null, current) == current)
        {
            RefreshEngineHealth();
        }
    }

    private void RefreshQueueHealth()
    {
        var currentCaptureQueue = captureQueue;
        var currentInjectionQueue = injectionQueue;
        var degraded = Volatile.Read(ref transientDegradedReason);
        if (degraded is null)
        {
            return;
        }

        if (degraded.StartsWith("Capture processing queue", StringComparison.Ordinal) &&
            currentCaptureQueue is not null &&
            currentCaptureQueue.BufferedBytes <= CaptureQueueMaximumBytes / 4)
        {
            ClearTransientDegraded("Capture processing queue");
        }
        else if (degraded.StartsWith("Forwarding injection queue", StringComparison.Ordinal) &&
                 currentInjectionQueue is not null &&
                 currentInjectionQueue.ForwardingQueueBytes <= ForwardingQueueMaximumBytes / 4)
        {
            ClearTransientDegraded("Forwarding injection queue");
        }
    }

    private void RefreshEngineHealth()
    {
        var healthy = IsRunning &&
                      backgroundFailure is null &&
                      Volatile.Read(ref transientDegradedReason) is null &&
                      backgroundTask?.IsCompleted != true;
        var newValue = healthy ? 1 : 0;
        var previous = Interlocked.Exchange(ref engineHealthy, newValue);
        if (previous != newValue)
        {
            var message = healthy
                ? "Packet capture and processing queues recovered; enforcement health is restored."
                : "Packet processing health is degraded.";
            RaiseStatus(message);
            RaiseStateChanged(IsRunning, message, isHealthy: healthy);
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
        _ = ResolveNameSafelyAsync(arp.SenderIp, arp.SenderMac);
        RespondToArpRequest(arp);
        if (controlling && needsPoison)
        {
            PoisonClient(
                new KeyValuePair<IPAddress, PhysicalAddress>(
                    arp.SenderIp,
                    arp.SenderMac));
        }
    }

    private async Task ResolveNameSafelyAsync(IPAddress address, PhysicalAddress mac)
    {
        try
        {
            await ResolveNameAsync(address, mac);
        }
        catch (Exception exception)
        {
            // Name resolution is optional inventory work. Surface its failure
            // without allowing a fire-and-forget task to become unobserved or
            // to stop packet forwarding.
            RaiseStatus($"Optional name resolution failed for {address}: {exception.Message}");
        }
    }

    private async Task ResolveNameAsync(IPAddress address, PhysicalAddress mac)
    {
        var key = mac.ToString();
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
            BackgroundLoopSupervisor.RunAsync(
                "ARP enforcement loop",
                () => RunPoisonLoopAsync(cancellationToken),
                cancellationToken,
                HandleBackgroundFailure),
            BackgroundLoopSupervisor.RunAsync(
                "Device presence loop",
                () => RunPresenceProbeLoopAsync(cancellationToken),
                cancellationToken,
                HandleBackgroundFailure));

    private async Task RunPoisonLoopAsync(CancellationToken cancellationToken)
    {
        using var poisonTimer = new PeriodicTimer(TimeSpan.FromSeconds(5));
        while (await poisonTimer.WaitForNextTickAsync(cancellationToken))
        {
            PoisonClients();
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
                await SendRestoreFramesAsync(pair, activeProfile, activeGatewayMac);
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

            await SendRestoreFramesAsync(client, activeProfile, activeGatewayMac);
            PoisonClient(client);
            if (attempt < 2)
            {
                await Task.Delay(40);
            }
        }
    }

    private async Task SendRestoreFramesAsync(
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
        await SendArpPacketAsync(restoreFrames.ToClient);
        await SendArpPacketAsync(restoreFrames.ToGateway);

        // Also ask a connected client to answer the gateway itself. The direct
        // replies above cover clients that disconnected before restoration.
        var recoveryRequest = ArpInterceptionFrames.BuildRecoveryRequest(
            activeProfile.LocalMac,
            activeGatewayMac,
            activeProfile.GatewayAddress,
            client.Value,
            client.Key);
        await SendArpPacketAsync(recoveryRequest);
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
        var activeQueue = injectionQueue;
        if (activeQueue is null || injectionWorkerTask?.IsCompleted == true)
        {
            SendArpPacketDirect(bytes);
            return;
        }

        try
        {
            activeQueue.EnqueuePriority(
            bytes,
            RecordArpInjectionSuccess,
            RecordArpQueueLatency);
        }
        catch (InvalidOperationException exception)
        {
            HandleBackgroundFailure("ARP priority injection queue", exception);
            throw;
        }
    }

    private async Task SendArpPacketAsync(
        byte[] bytes,
        CancellationToken cancellationToken = default)
    {
        var activeQueue = injectionQueue;
        if (activeQueue is null || injectionWorkerTask?.IsCompleted == true)
        {
            await ArpEnforcementRetry.ExecuteAsync(
                () => SendArpPacketDirect(bytes),
                cancellationToken,
                OnInjectionRetry);
            return;
        }

        try
        {
            await activeQueue.SendPriorityAsync(
                bytes,
                cancellationToken,
                RecordArpInjectionSuccess,
                RecordArpQueueLatency);
        }
        catch (InvalidOperationException exception)
        {
            HandleBackgroundFailure("ARP priority injection queue", exception);
            throw;
        }
    }

    private void SendArpPacketDirect(byte[] bytes)
    {
        var activeDevice = arpDevice ??
            throw new InvalidOperationException("The ARP capture adapter is not open.");
        try
        {
            lock (arpSendSync)
            {
                activeDevice.SendPacket(bytes);
            }

            RecordArpInjectionSuccess();
        }
        catch (Exception exception)
        {
            var adapterName = profile?.Name ?? "unknown adapter";
            Interlocked.Increment(ref injectionSendFailures);
            throw new InvalidOperationException(
                $"Npcap rejected an ARP packet on '{adapterName}' " +
                $"({bytes.Length} bytes): {exception.Message}",
                exception);
        }
    }

    private void SendInjectionPacket(byte[] bytes)
    {
        // Some Wi-Fi drivers accept injection only through the established ARP
        // handle. All post-start sends are serialized by this dedicated worker,
        // so forwarding can no longer hold the send lock ahead of ARP refreshes.
        var activeDevice = PacketInjectionPolicy.SelectHandle(arpDevice, forwardingDevice);
        try
        {
            activeDevice.SendPacket(bytes);
        }
        catch (Exception exception)
        {
            Interlocked.Increment(ref injectionSendFailures);
            var adapterName = profile?.Name ?? "unknown adapter";
            throw new InvalidOperationException(
                $"Npcap rejected a packet on '{adapterName}' ({bytes.Length} bytes): " +
                $"{exception.Message}",
                exception);
        }
    }

    private void RecordArpInjectionSuccess() =>
        Interlocked.Exchange(ref lastArpInjectionUtcTicks, DateTimeOffset.UtcNow.UtcTicks);

    private void RecordArpQueueLatency(TimeSpan latency) =>
        Interlocked.Exchange(ref lastArpQueueLatencyTicks, latency.Ticks);

    private void RecordForwardingQueueLatency(TimeSpan latency) =>
        Interlocked.Exchange(ref lastForwardingQueueLatencyTicks, latency.Ticks);

    private void UpdatePerformanceMetrics(uint newlyReceivedPackets)
    {
        var now = Stopwatch.GetTimestamp();
        var elapsedSeconds = lastCaptureStatisticsTimestamp == 0
            ? 0
            : Stopwatch.GetElapsedTime(lastCaptureStatisticsTimestamp, now).TotalSeconds;
        lastCaptureStatisticsTimestamp = now;

        var currentCaptureBytes = Interlocked.Read(ref captureBytes);
        var currentForwardedPackets = ForwardedPacketCount;
        var currentForwardedBytes = Interlocked.Read(ref forwardedBytes);

        if (elapsedSeconds > 0)
        {
            var captureByteDelta = Math.Max(0, currentCaptureBytes - previousCaptureBytesSample);
            var forwardedPacketDelta = Math.Max(0, currentForwardedPackets - previousForwardedPacketsSample);
            var forwardedByteDelta = Math.Max(0, currentForwardedBytes - previousForwardedBytesSample);

            Interlocked.Exchange(
                ref capturePacketsPerSecondMilli,
                (long)(newlyReceivedPackets / elapsedSeconds * 1000));
            Interlocked.Exchange(
                ref captureBytesPerSecond,
                (long)(captureByteDelta / elapsedSeconds));
            Interlocked.Exchange(
                ref forwardedPacketsPerSecondMilli,
                (long)(forwardedPacketDelta / elapsedSeconds * 1000));
            Interlocked.Exchange(
                ref forwardedBytesPerSecond,
                (long)(forwardedByteDelta / elapsedSeconds));
        }

        previousCaptureBytesSample = currentCaptureBytes;
        previousForwardedPacketsSample = currentForwardedPackets;
        previousForwardedBytesSample = currentForwardedBytes;

        try
        {
            using var process = Process.GetCurrentProcess();
            var currentCpuTicks = process.TotalProcessorTime.Ticks;
            if (previousProcessCpuTimestamp != 0)
            {
                var wallSeconds = Stopwatch.GetElapsedTime(
                    previousProcessCpuTimestamp,
                    now).TotalSeconds;
                var cpuSeconds = Math.Max(
                    0,
                    currentCpuTicks - previousProcessCpuTicks) /
                    (double)TimeSpan.TicksPerSecond;
                if (wallSeconds > 0)
                {
                    var cpuPercent = Math.Clamp(
                        cpuSeconds / (wallSeconds * Environment.ProcessorCount) * 100,
                        0,
                        100);
                    Interlocked.Exchange(
                        ref processCpuMilliPercent,
                        (long)(cpuPercent * 1000));
                }
            }

            previousProcessCpuTicks = currentCpuTicks;
            previousProcessCpuTimestamp = now;
        }
        catch (Exception exception) when (
            exception is InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            RaiseStatus($"LANtern process CPU usage is unavailable: {exception.Message}");
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
        var failure = $"{source}: {exception}";
        if (Interlocked.CompareExchange(ref backgroundFailure, failure, null) is not null)
        {
            return;
        }

        controlling = false;
        Volatile.Write(ref engineHealthy, 0);
        RaiseStatus($"{failure}; enforcement is degraded and a serialized network restoration is starting.");
        RaiseStateChanged(
            IsRunning,
            $"{source} failed. Control is no longer enforcing policy; restoring network connectivity.",
            failure,
            isHealthy: false);

        // Do not cancel or dispose the lifetime token from this callback. The
        // lifecycle gate serializes the ensuing shutdown with an in-progress start.
        _ = Task.Run(async () =>
        {
            try
            {
                await StopAsync();
            }
            catch (Exception stopException)
            {
                RaiseStatus($"Automatic safe shutdown failed: {stopException}");
            }
        });
    }

    private void RaiseStatus(string message) => StatusChanged?.Invoke(this, message);

    private void RaiseStateChanged(
        bool isRunning,
        string statusMessage,
        string? failureMessage = null,
        bool? isHealthy = null) =>
        StateChanged?.Invoke(
            this,
            new PcapEngineStateChangedEventArgs(
                isRunning,
                statusMessage,
                failureMessage,
                isHealthy));
}
