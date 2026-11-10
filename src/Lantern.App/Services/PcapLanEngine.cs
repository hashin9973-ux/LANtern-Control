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
    private readonly object injectionSendSync = new();
    private readonly object temporaryProbeSendSync = new();
    private const long CaptureQueueMaximumBytes = 32 * 1024 * 1024;
    private const long ForwardingQueueMaximumBytes = 32 * 1024 * 1024;
    private const long PriorityQueueMaximumBytes = 1024 * 1024;
    private const double QueuePressureThreshold = 0.75;
    private static readonly TimeSpan MaximumArpQueueWait = TimeSpan.FromMilliseconds(500);
    private static readonly TimeSpan MaximumForwardingQueueWait = TimeSpan.FromMilliseconds(250);
    private static readonly TimeSpan QueueWaitSampleFreshness = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan CaptureStatisticsInterval = TimeSpan.FromSeconds(2);
    private static readonly TimeSpan MaximumArpEnforcementSilence = TimeSpan.FromSeconds(15);
    private readonly SemaphoreSlim refreshSync = new(1, 1);
    private readonly AsyncTransitionLock lifecycleGate = new();
    private readonly EngineDiagnosticLog diagnosticLog = new();
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
    private readonly EngineHealthFaultRegistry healthFaults = new();
    private readonly EngineHealthState healthState = new();
    private string? captureStatisticsWarning;
    private uint previousCaptureReceived;
    private uint previousCaptureDropped;
    private bool captureStatisticsInitialized;
    private long lastInjectionHandleRecoveryUtcTicks;
    private long injectionHandleReopenCount;
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
    private long lastArpEnforcementUtcTicks;
    private long lastForwardedInjectionUtcTicks;
    private LibPcapLiveDevice? arpDevice;
    private LibPcapLiveDevice? forwardingDevice;
    private LibPcapLiveDevice? injectionDevice;
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

    public bool IsRunning =>
        profile is not null ||
        engineCancellation is not null ||
        arpDevice is not null ||
        forwardingDevice is not null ||
        injectionDevice is not null;

    public bool IsHealthy => healthState.IsHealthy && AreHealthPrerequisitesSatisfied();

    private bool AreHealthPrerequisitesSatisfied() =>
        IsRunning &&
        arpDevice?.Opened == true &&
        forwardingDevice?.Opened == true &&
        injectionDevice?.Opened == true &&
        controlling &&
        !restoring &&
        backgroundFailure is null &&
        healthFaults.IsHealthy &&
        Volatile.Read(ref captureStatisticsWarning) is null &&
        pcapRuntimeInfo?.NativeLibraryPath is not null &&
        GetLiveHealthWarning() is null &&
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
            injectionDevice?.Opened == true,
            backgroundFailure ??
                GetTransientDegradedReason() ??
                Volatile.Read(ref captureStatisticsWarning) ??
                GetLiveHealthWarning() ??
                (!controlling || restoring ? "The controller is not actively enforcing policy." : null) ??
                (arpDevice?.Opened != true ? "The ARP capture handle is closed." : null) ??
                (forwardingDevice?.Opened != true ? "The IPv4 capture handle is closed." : null) ??
                (injectionDevice?.Opened != true ? "The dedicated injection handle is closed." : null) ??
                (runtime?.NativeLibraryPath is null ? runtime?.Error : null),
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
            Interlocked.Read(ref injectionHandleReopenCount),
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
            ReadTimestamp(Interlocked.Read(ref lastArpEnforcementUtcTicks)),
            ReadTimestamp(Interlocked.Read(ref lastForwardedInjectionUtcTicks)),
            ReadTimestamp(Interlocked.Read(ref lastInjectionHandleRecoveryUtcTicks)),
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
        using var lifecycleTransition = await lifecycleGate.EnterAsync(cancellationToken);
        if (IsRunning)
        {
            return;
        }

        diagnosticLog.Write(
            "controller.starting",
            "lifecycle",
            adapter.Name,
            "starting",
            "user-requested-start");
        try
        {
            await NpfDriverService.EnsureAvailableAsync(cancellationToken);
            profile = adapter;
            clientMappings.BeginAdapter(adapter.Id);
            // Presence-probe scheduling is per controller session. Reset it so
            // known clients are actively revalidated before any saved rule is
            // reported as running on this adapter.
            lastPresenceProbeAt.Clear();
            lastPresenceProbeBatchAt = DateTimeOffset.MinValue;
            presenceProbeAdapterId = adapter.Id;
            lastDiscoveryProbeBatchAt = DateTimeOffset.MinValue;
            resolvedNameClaims.Reset(rejectedResolvedNames);
            resolvingNames.Clear();
            registry.BeginSession();
            identityMonitor.Reset();
            SeedRememberedInventory();

            var clients = clientMappings.Mappings;
            restoring = false;
            controlling = false;
            backgroundFailure = null;
            healthFaults.Clear();
            healthState.BeginStart();
            Interlocked.Exchange(ref lastInjectionHandleRecoveryUtcTicks, 0);
            Interlocked.Exchange(ref injectionHandleReopenCount, 0);
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
            Interlocked.Exchange(ref lastArpEnforcementUtcTicks, 0);
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

            arpDevice = captureDevice;
                arpDevice.OnPacketArrival += OnArpPacketArrival;
                arpDevice.Open(PcapCaptureConfiguration.CreateForArpDiscovery());
                arpDevice.Filter = "arp";
                arpDevice.StartCapture();

                var captureInterface = captureDevice.Interface ??
                    throw new InvalidOperationException("The capture adapter has no interface.");
                forwardingDevice = new LibPcapLiveDevice(captureInterface);
                forwardingDevice.Open(PcapCaptureConfiguration.CreateForForwarding());
                forwardingDevice.Filter = "ip";

                // Keep packet writes on a dedicated handle. The ARP and IPv4
                // receive handles are owned only by their capture readers.
                injectionDevice = new LibPcapLiveDevice(captureInterface);
                injectionDevice.Open(PcapCaptureConfiguration.CreateForInjection());
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
                    (attempt, exception) =>
                        OnInjectionRetry("ARP enforcement", attempt, exception));

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

                // These synchronous, CPU/native-I/O loops each get a dedicated
                // worker thread. They must not depend on ThreadPool growth when
                // gameplay traffic or UI/script work saturates the shared pool.
                var captureTask = BackgroundLoopSupervisor.RunAsync(
                    "Npcap capture loop",
                    () => Task.Factory.StartNew(
                        () => RunForwardingLoop(engineToken, forwarderStarted),
                        engineToken,
                        TaskCreationOptions.LongRunning,
                        TaskScheduler.Default),
                    engineToken,
                    HandleBackgroundFailure);

                var processingTask = BackgroundLoopSupervisor.RunAsync(
                    "Packet processing loop",
                    () => Task.Factory.StartNew(
                        () => RunPacketProcessingLoop(engineToken),
                        engineToken,
                        TaskCreationOptions.LongRunning,
                        TaskScheduler.Default),
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

                // Revalidate only addresses already present in remembered
                // inventory / the Windows neighbor cache. This is deliberately
                // not a subnet scan: unknown addresses remain user-initiated.
                RaiseStatus("Verifying previously discovered devices for traffic control…");
                var startupPresence = await ProbeAddressesAsync(
                    adapter,
                    force: true,
                    cancellationToken);
                diagnosticLog.Write(
                    "controller.startup-presence-probe-completed",
                    "device presence",
                    profile?.Name,
                    "running",
                    $"Sent {startupPresence.RequestsSent} known-client ARP probe(s); " +
                    $"{startupPresence.DevicesResponded} verified client(s) replied.");

                if (backgroundFailure is not null ||
                    !IsRunning ||
                    arpDevice?.Opened != true ||
                    forwardingDevice?.Opened != true ||
                    injectionDevice?.Opened != true ||
                    backgroundTask?.IsCompleted == true)
                {
                    throw new InvalidOperationException(
                        backgroundFailure ?? "A required packet-processing worker failed during startup.");
                }

                PoisonClients();
                healthState.CompleteStart(AreHealthPrerequisitesSatisfied());
                var presenceMessage = startupPresence.RequestsSent == 0
                    ? "No previously discovered client addresses were available to verify. Run Scan devices before applying a device rule."
                    : startupPresence.DevicesResponded == 0
                        ? "No previously discovered clients replied to the startup ARP checks. Rules cannot be enforced until a client is reachable and verified."
                        : $"Verified {startupPresence.DevicesResponded} previously discovered client(s) for control.";
                var activeMessage = IsHealthy
                    ? $"Control is running — packet capture, queue pressure, Npcap drops, and injection health are being monitored. {presenceMessage}"
                    : $"Control is running in DEGRADED mode: {GetHealthSnapshot().Failure ?? "packet health could not be fully verified."} {presenceMessage}";
                diagnosticLog.Write(
                    "controller.running",
                    "lifecycle",
                    profile?.Name,
                    "running",
                    activeMessage);
                RaiseStatus(activeMessage);
                RaiseStateChanged(true, activeMessage, isHealthy: IsHealthy);
            }
            catch (Exception exception)
            {
                diagnosticLog.Write(
                    "controller.start-failed",
                    "lifecycle",
                    profile?.Name,
                    "faulted",
                    "StartAsync did not complete.",
                    exception);
                var failure = backgroundFailure;
                Interlocked.CompareExchange(
                    ref backgroundFailure,
                    $"Startup failed: {exception.Message}",
                    null);
                healthState.MarkDegraded();
                controlling = false;
                await StopCoreAsync("startup-failure");
                if (failure is not null)
                {
                    throw new InvalidOperationException(failure, exception);
                }

                throw;
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
                    NotifyObserver(
                    "ARP identity alert",
                    () => IdentityAlertDetected?.Invoke(this, observation.Warning));
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
            // Track replies from the active capture callback for both targeted
            // presence checks and explicit discovery. The same verified ARP
            // observation also populates clientMappings for packet forwarding.
            BeginTemporaryProbeContext(activeProfile, targets, responders, createIdentityMonitor: false);
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
                EndTemporaryProbeContext();
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
                    lock (temporaryProbeSendSync)
                    {
                        NpcapSendQueueTransmitter.Send(
                            captureDevice,
                            EthernetFrameCodec.PadToMinimumEthernetFrameSize(bytes));
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
        try
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
            NotifyObserver(
                "ARP identity alert",
                () => IdentityAlertDetected?.Invoke(this, identity.Warning));
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
        catch (Exception exception)
        {
            diagnosticLog.Write(
                "discovery.packet-callback-failed",
                "temporary ARP discovery callback",
                temporaryProbeProfile?.Name,
                "running",
                "A discovery-only ARP callback failed; controller forwarding is unaffected.",
                exception);
            RaiseStatus($"A discovery-only packet callback failed: {exception.Message}");
        }
    }

    public async Task StopAsync(string reason = "user-requested")
    {
        using var lifecycleTransition = await lifecycleGate.EnterAsync();
        await StopCoreAsync(reason);
    }

    private async Task StopCoreAsync(string reason)
    {
        if (!IsRunning && profile is null && engineCancellation is null)
        {
            return;
        }

        diagnosticLog.Write(
            "controller.stopping",
            "lifecycle",
            profile?.Name,
            "stopping",
            reason);
        controlling = false;
        healthState.MarkDegraded();

        // Let an in-flight presence/discovery probe finish before restoration.
        // Once the semaphore is acquired, no maintenance probe can enqueue ARP
        // frames ahead of corrective mappings.
        var shutdownWarnings = new List<string>();
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
            catch (Exception exception)
            {
                var warning = $"Network restoration failed: {exception.Message}";
                shutdownWarnings.Add(warning);
                diagnosticLog.Write(
                    "network.restoration-failed",
                    "ARP restoration",
                    profile?.Name,
                    "degraded",
                    "Network restoration failed; handle cleanup will continue.",
                    exception);
                RaiseStatus($"{warning}; closing capture handles safely.");
            }
        }
        finally
        {
            refreshSync.Release();
        }

        var activeArpDevice = arpDevice;
        if (activeArpDevice is not null)
        {
            AttemptDeviceCleanup(
                "ARP capture stop",
                () => activeArpDevice.StopCapture(),
                shutdownWarnings);
            AttemptDeviceCleanup(
                "ARP event unsubscription",
                () => activeArpDevice.OnPacketArrival -= OnArpPacketArrival,
                shutdownWarnings);
            AttemptDeviceCleanup(
                "ARP capture close",
                activeArpDevice.Close,
                shutdownWarnings);
            arpDevice = null;
        }

        var activeForwardingDevice = forwardingDevice;
        if (activeForwardingDevice is not null)
        {
            AttemptDeviceCleanup(
                "forwarding capture close",
                activeForwardingDevice.Close,
                shutdownWarnings);
            forwardingDevice = null;
        }

        var activeInjectionDevice = injectionDevice;
        if (activeInjectionDevice is not null)
        {
            AttemptDeviceCleanup(
                "packet injection handle close",
                activeInjectionDevice.Close,
                shutdownWarnings);
            injectionDevice = null;
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
        healthState.Stop();
        var shutdownWarning = shutdownWarnings.Count == 0
            ? null
            : string.Join(" | ", shutdownWarnings);
        var failure = backgroundFailure ?? shutdownWarning;
        var stoppedMessage = backgroundFailure is not null
            ? $"Stopped after an engine error: {backgroundFailure}. Corrective ARP mappings were attempted."
            : shutdownWarning is not null
                ? $"Stopped with a network-restoration or handle-cleanup warning: {shutdownWarning}"
                : "Stopped. Corrective ARP mappings were sent.";
        diagnosticLog.Write(
            "controller.stopped",
            "lifecycle",
            null,
            "stopped",
            failure ?? reason);
        RaiseStatus(stoppedMessage);
        RaiseStateChanged(false, stoppedMessage, failure, isHealthy: false);
    }

    private void AttemptDeviceCleanup(
        string component,
        Action cleanup,
        ICollection<string> warnings)
    {
        try
        {
            cleanup();
        }
        catch (Exception exception)
        {
            var warning = $"{component} failed: {exception.Message}";
            warnings.Add(warning);
            diagnosticLog.Write(
                "capture-handle.cleanup-failed",
                component,
                profile?.Name,
                "degraded",
                warning,
                exception);
            RaiseStatus(warning);
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
            KeyValuePair<IPAddress, PhysicalAddress>? matchedClient = null;
            foreach (var client in clients)
            {
                if (string.Equals(
                        TrafficPolicy.NormalizeMac(client.Value.ToString()),
                        normalizedMac,
                        StringComparison.Ordinal))
                {
                    matchedClient = client;
                    break;
                }
            }

            if (matchedClient is null)
            {
                throw new InvalidOperationException(
                    $"The rule for {normalizedMac} could not be enforced yet: " +
                    "there is no verified live IP/MAC mapping for this device. " +
                    "Run Scan devices while Control is running, then apply the rule again.");
            }

            await ApplyInterceptionTransitionAsync(
                matchedClient.Value,
                InterceptionTransition.Between(previousTargets, currentTargets));
        }
    }

    public async ValueTask DisposeAsync()
    {
        await StopAsync("dispose");
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
        catch (Exception exception)
        {
            if (!restoring)
            {
                HandleBackgroundFailure("ARP packet handling failed", exception);
            }
            else
            {
                diagnosticLog.Write(
                    "packet-callback.failed-during-stop",
                    "ARP packet callback",
                    profile?.Name,
                    "stopping",
                    "ARP callback failed while network restoration was in progress.",
                    exception);
            }
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

    private void RunPacketProcessingLoop(CancellationToken cancellationToken)
    {
        var activeQueue = captureQueue ??
            throw new InvalidOperationException("The capture processing queue is not available.");

        while (true)
        {
            var packet = activeQueue.ReadAsync(cancellationToken)
                .AsTask()
                .GetAwaiter()
                .GetResult();
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
            NotifyObserver(
                "device identity notification",
                () => DeviceIdentityLearned?.Invoke(
                    this,
                    new DeviceIdentityLearnedEventArgs(
                        dhcpHost.MacAddress,
                        dhcpHost.HostName)));
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
            NotifyObserver(
                "domain activity notification",
                () => DeviceDomainObserved?.Invoke(
                    this,
                    new DeviceDomainObservedEventArgs(
                        result.ClientMac,
                        observation,
                        DateTimeOffset.UtcNow,
                        result.BlockedByDomain)));
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
        var key = GetDegradationKey(reason);
        if (!healthFaults.TrySet(key, reason))
        {
            return;
        }

        healthState.MarkDegraded();
        diagnosticLog.Write(
            "packet-health.degraded",
            "packet-processing",
            profile?.Name,
            "degraded",
            reason);
        RaiseStatus($"Packet processing health degraded: {reason}");
        RaiseStateChanged(
            IsRunning,
            $"Packet processing health degraded: {reason}",
            isHealthy: false);
    }

    private static string GetDegradationKey(string reason)
    {
        if (reason.StartsWith("Capture processing queue", StringComparison.Ordinal))
        {
            return "capture-queue";
        }

        if (reason.StartsWith("Forwarding injection queue", StringComparison.Ordinal))
        {
            return "forwarding-queue";
        }

        if (reason.StartsWith("ARP priority injection queue", StringComparison.Ordinal))
        {
            return "priority-queue";
        }

        if (reason.StartsWith("Npcap reported", StringComparison.Ordinal))
        {
            return "npcap-drops";
        }

        if (reason.StartsWith("Npcap capture statistics", StringComparison.Ordinal))
        {
            return "npcap-statistics";
        }

        if (reason.StartsWith("Capture library", StringComparison.Ordinal))
        {
            return "native-library";
        }

        return reason;
    }

    private string? GetTransientDegradedReason() => healthFaults.PrimaryReason;

    private void ClearTransientDegraded(string expectedPrefix)
    {
        if (healthFaults.TryClear(GetDegradationKey(expectedPrefix)))
        {
            RefreshEngineHealth();
        }
    }

    private void RefreshQueueHealth()
    {
        var currentCaptureQueue = captureQueue;
        var currentInjectionQueue = injectionQueue;
        if (currentCaptureQueue is not null &&
            currentCaptureQueue.BufferedBytes >= CaptureQueueMaximumBytes * QueuePressureThreshold)
        {
            SetTransientDegraded(
                $"Capture processing queue pressure is high ({currentCaptureQueue.BufferedBytes / 1024:N0} KiB buffered).");
        }

        if (currentInjectionQueue is not null &&
            currentInjectionQueue.ForwardingQueueBytes >= ForwardingQueueMaximumBytes * QueuePressureThreshold)
        {
            SetTransientDegraded(
                $"Forwarding injection queue pressure is high ({currentInjectionQueue.ForwardingQueueBytes / 1024:N0} KiB buffered).");
        }

        if (currentInjectionQueue is not null &&
            currentInjectionQueue.PriorityQueueBytes >= PriorityQueueMaximumBytes * QueuePressureThreshold)
        {
            SetTransientDegraded(
                $"ARP priority injection queue pressure is high ({currentInjectionQueue.PriorityQueueBytes / 1024:N0} KiB buffered).");
        }

        if (currentCaptureQueue is not null &&
            currentCaptureQueue.BufferedBytes <= CaptureQueueMaximumBytes / 4)
        {
            ClearTransientDegraded("Capture processing queue");
        }

        if (currentInjectionQueue is not null &&
            currentInjectionQueue.ForwardingQueueBytes <= ForwardingQueueMaximumBytes / 4)
        {
            ClearTransientDegraded("Forwarding injection queue");
        }

        if (currentInjectionQueue is not null &&
            currentInjectionQueue.PriorityQueueBytes <= PriorityQueueMaximumBytes / 4)
        {
            ClearTransientDegraded("ARP priority injection queue");
        }
    }

    private string? GetLiveHealthWarning()
    {
        var nowUtcTicks = DateTimeOffset.UtcNow.UtcTicks;
        var hasInterceptionTargets = clientMappings.Mappings.Any(
            client => policy.GetInterceptionTargets(client.Value.ToString()) != InterceptionTargets.None);
        var lastArpEnforcementUtcTicks = Interlocked.Read(ref this.lastArpEnforcementUtcTicks);
        if (ArpEnforcementHealthPolicy.IsStale(
                hasInterceptionTargets,
                lastArpEnforcementUtcTicks,
                nowUtcTicks,
                MaximumArpEnforcementSilence))
        {
            var age = lastArpEnforcementUtcTicks <= 0
                ? "no successful paused-device enforcement injection has been recorded"
                : $"the last successful paused-device enforcement injection was " +
                  $"{TimeSpan.FromTicks(nowUtcTicks - lastArpEnforcementUtcTicks).TotalSeconds:N1} seconds ago";
            return $"Paused-device ARP enforcement is stale: {age}.";
        }

        var currentCaptureQueue = captureQueue;
        if (currentCaptureQueue is not null &&
            currentCaptureQueue.BufferedBytes >= CaptureQueueMaximumBytes * QueuePressureThreshold)
        {
            return "Capture processing queue is above 75% capacity.";
        }

        var currentInjectionQueue = injectionQueue;
        if (currentInjectionQueue is not null &&
            currentInjectionQueue.PriorityQueueBytes >= PriorityQueueMaximumBytes * QueuePressureThreshold)
        {
            return "ARP priority injection queue is above 75% capacity.";
        }

        if (currentInjectionQueue is not null &&
            currentInjectionQueue.ForwardingQueueBytes >= ForwardingQueueMaximumBytes * QueuePressureThreshold)
        {
            return "Forwarding injection queue is above 75% capacity.";
        }

        var arpSampleUtcTicks = Interlocked.Read(ref lastArpInjectionUtcTicks);
        var arpLatency = TimeSpan.FromTicks(Interlocked.Read(ref lastArpQueueLatencyTicks));
        if (IsFreshQueueWaitSample(nowUtcTicks, arpSampleUtcTicks) &&
            arpLatency > MaximumArpQueueWait)
        {
            return $"ARP injection queue wait is {arpLatency.TotalMilliseconds:N0} ms.";
        }

        var forwardingSampleUtcTicks = Interlocked.Read(ref lastForwardedInjectionUtcTicks);
        var forwardingLatency = TimeSpan.FromTicks(
            Interlocked.Read(ref lastForwardingQueueLatencyTicks));
        if (IsFreshQueueWaitSample(nowUtcTicks, forwardingSampleUtcTicks) &&
            forwardingLatency > MaximumForwardingQueueWait)
        {
            return $"Forwarding injection queue wait is {forwardingLatency.TotalMilliseconds:N0} ms.";
        }

        return null;
    }

    private bool IsFreshQueueWaitSample(long nowUtcTicks, long successfulInjectionUtcTicks) =>
        successfulInjectionUtcTicks > 0 &&
        nowUtcTicks >= successfulInjectionUtcTicks &&
        nowUtcTicks - successfulInjectionUtcTicks <= QueueWaitSampleFreshness.Ticks;

    private void RefreshEngineHealth()
    {
        if (healthState.Refresh(AreHealthPrerequisitesSatisfied()))
        {
            var healthy = IsHealthy;
            var message = healthy
                ? "Packet capture and processing queues recovered; enforcement health is restored."
                : "Packet processing health is degraded.";
            if (healthy)
            {
                diagnosticLog.Write(
                    "packet-health.recovered",
                    "packet-processing",
                    profile?.Name,
                    "healthy",
                    message);
            }

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
            NotifyObserver(
                "ARP identity alert",
                () => IdentityAlertDetected?.Invoke(this, identity.Warning));
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
                        NotifyObserver(
                            "device identity notification",
                            () => DeviceIdentityLearned?.Invoke(
                                this,
                                new DeviceIdentityLearnedEventArgs(mac, acceptedName)));
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

        // Re-evaluate active enforcement after every scheduled poison cycle.
        RefreshEngineHealth();
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
            SendArpPacket(frame, isEnforcement: true);
        }

        var controllerFrames = ArpInterceptionFrames.BuildControllerProtection(
            activeProfile.LocalMac,
            activeProfile.LocalAddress,
            activeGatewayMac,
            activeProfile.GatewayAddress,
            client.Value,
            client.Key);
        SendArpPacket(controllerFrames.ClientToController, isEnforcement: true);
        SendArpPacket(controllerFrames.GatewayToController, isEnforcement: true);
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
            SendArpPacket(frames.ToClient, isEnforcement: true);
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
            SendArpPacket(frames.ToGateway, isEnforcement: true);
        }
    }

    private void SendArpPacket(byte[] bytes, bool isEnforcement = false)
    {
        var activeQueue = injectionQueue;
        if (activeQueue is null || injectionWorkerTask?.IsCompleted == true)
        {
            SendArpPacketDirect(bytes, isEnforcement);
            return;
        }

        try
        {
            activeQueue.EnqueuePriority(
            bytes,
            isEnforcement ? RecordArpEnforcementSuccess : RecordArpInjectionSuccess,
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
                (attempt, exception) =>
                    OnInjectionRetry("ARP enforcement", attempt, exception));
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

    private void SendArpPacketDirect(byte[] bytes, bool isEnforcement = false)
    {
        SendInjectionPacket(bytes, "ARP");
        if (isEnforcement)
        {
            RecordArpEnforcementSuccess();
        }
        else
        {
            RecordArpInjectionSuccess();
        }
    }

    private void SendInjectionPacket(byte[] bytes) =>
        SendInjectionPacket(bytes, "packet");

    private void SendInjectionPacket(byte[] bytes, string packetKind)
    {
        // ARP builders produce 42-byte Ethernet frames. Normalize every
        // egress packet before queuing it for Npcap.
        var transmissionFrame = EthernetFrameCodec.PadToMinimumEthernetFrameSize(bytes);

        lock (injectionSendSync)
        {
            var activeDevice = PacketInjectionPolicy.SelectInjectionHandle(injectionDevice);
            try
            {
                // Use pcap_sendqueue_transmit (PacketSendPackets on Windows),
                // not pcap_sendpacket (PacketSendPacket). These are distinct
                // Npcap send entry points, avoiding the single-packet path
                // that previously returned ERROR_GEN_FAILURE.
                NpcapSendQueueTransmitter.Send(activeDevice, transmissionFrame);
            }
            catch (Exception exception)
            {
                Interlocked.Increment(ref injectionSendFailures);
                var adapterName = profile?.Name ?? "unknown adapter";
                diagnosticLog.Write(
                    "packet-injection.native-send-queue-failed",
                    "Npcap native send queue",
                    adapterName,
                    "degraded",
                    $"Npcap could not submit a {packetKind} through the native send-queue path " +
                    $"({transmissionFrame.Length}-byte frame; {bytes.Length}-byte input).",
                    exception);
                throw new InvalidOperationException(
                    $"Npcap native send queue failed for {packetKind} on '{adapterName}' " +
                    $"({transmissionFrame.Length}-byte frame; {bytes.Length}-byte input): {exception.Message}",
                    exception);
            }
        }
    }

    private void RecordArpInjectionSuccess()
    {
        Interlocked.Exchange(ref lastArpInjectionUtcTicks, DateTimeOffset.UtcNow.UtcTicks);
        RefreshEngineHealth();
    }

    private void RecordArpEnforcementSuccess()
    {
        var nowUtcTicks = DateTimeOffset.UtcNow.UtcTicks;
        Interlocked.Exchange(ref lastArpEnforcementUtcTicks, nowUtcTicks);
        Interlocked.Exchange(ref lastArpInjectionUtcTicks, nowUtcTicks);
        RefreshEngineHealth();
    }

    private void RecordArpQueueLatency(TimeSpan latency)
    {
        Interlocked.Exchange(ref lastArpQueueLatencyTicks, latency.Ticks);
        var activeQueue = injectionQueue;
        if (activeQueue is not null &&
            activeQueue.PriorityQueueBytes <= PriorityQueueMaximumBytes / 4)
        {
            ClearTransientDegraded("ARP priority injection queue");
        }
    }

    private void RecordForwardingQueueLatency(TimeSpan latency)
    {
        Interlocked.Exchange(ref lastForwardingQueueLatencyTicks, latency.Ticks);
        var activeQueue = injectionQueue;
        if (activeQueue is not null &&
            activeQueue.ForwardingQueueBytes <= ForwardingQueueMaximumBytes / 4)
        {
            ClearTransientDegraded("Forwarding injection queue");
        }
    }

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
        healthState.MarkDegraded();
        diagnosticLog.Write(
            "controller.faulted",
            source,
            profile?.Name,
            "faulted",
            failure,
            exception);
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
                await StopAsync("background-failure");
            }
            catch (Exception stopException)
            {
                RaiseStatus($"Automatic safe shutdown failed: {stopException}");
            }
        });
    }

    private void NotifyObserver(string component, Action notification)
    {
        try
        {
            notification();
        }
        catch (Exception exception)
        {
            diagnosticLog.Write(
                "observer.notification-failed",
                component,
                profile?.Name,
                controlling ? "running" : "stopping",
                "A UI/inventory observer failed; packet processing continues.",
                exception);
        }
    }

    private void RaiseStatus(string message)
    {
        try
        {
            StatusChanged?.Invoke(this, message);
        }
        catch (Exception exception)
        {
            diagnosticLog.Write(
                "observer.status-notification-failed",
                "status notification",
                profile?.Name,
                controlling ? "running" : "stopping",
                message,
                exception);
        }
    }

    private void RaiseStateChanged(
        bool isRunning,
        string statusMessage,
        string? failureMessage = null,
        bool? isHealthy = null)
    {
        try
        {
            StateChanged?.Invoke(
                this,
                new PcapEngineStateChangedEventArgs(
                    isRunning,
                    statusMessage,
                    failureMessage,
                    isHealthy));
        }
        catch (Exception exception)
        {
            diagnosticLog.Write(
                "observer.state-notification-failed",
                "state notification",
                profile?.Name,
                isRunning ? "running" : "stopped",
                statusMessage,
                exception);
        }
    }
}
