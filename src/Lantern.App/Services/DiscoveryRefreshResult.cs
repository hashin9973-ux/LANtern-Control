namespace Lantern.App.Services;

public sealed record DiscoveryProbeResult(
    int RequestsSent,
    int RetryRequestsSent,
    int DevicesResponded,
    int CandidateHosts)
{
    public static DiscoveryProbeResult Empty { get; } = new(0, 0, 0, 0);
}

public sealed record DiscoveryRefreshResult(
    int CachedEntriesLoaded,
    int KnownDeviceCount,
    int ProbeRequestsSent = 0,
    string? ProbeWarning = null,
    int DevicesResponded = 0,
    int RetryRequestsSent = 0,
    int CandidateHosts = 0)
{
    public string StatusMessage => ProbeWarning is not null
        ? $"Device inventory refreshed — {CachedEntriesLoaded} neighbor-cache entries, " +
          $"{KnownDeviceCount} known devices. Local-network discovery was unavailable: {ProbeWarning}"
        : ProbeRequestsSent == 0
            ? $"Device inventory refreshed — {CachedEntriesLoaded} neighbor-cache entries, " +
              $"{KnownDeviceCount} known devices. No ARP discovery requests were needed during this pass."
            : $"Device inventory refreshed — {CachedEntriesLoaded} neighbor-cache entries, " +
              $"{KnownDeviceCount} known devices. ARP replies received from {DevicesResponded} of " +
              $"{CandidateHosts} candidate addresses after {ProbeRequestsSent} paced requests " +
              "(maximum 100 ARP requests per second) " +
              $"({RetryRequestsSent} retries).";
}
