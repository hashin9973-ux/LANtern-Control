namespace Lantern.App.Services;

public sealed record DiscoveryRefreshResult(
    int CachedEntriesLoaded,
    int KnownDeviceCount,
    int ProbeRequestsSent = 0,
    string? ProbeWarning = null)
{
    public string StatusMessage => ProbeWarning is not null
        ? $"Device inventory refreshed — {CachedEntriesLoaded} neighbor-cache entries, " +
          $"{KnownDeviceCount} known devices. Local-network discovery was unavailable: {ProbeWarning}"
        : ProbeRequestsSent == 0
            ? $"Device inventory refreshed — {CachedEntriesLoaded} neighbor-cache entries, " +
              $"{KnownDeviceCount} known devices. No discovery requests were sent; manual discovery is limited to one pass per minute."
            : $"Device inventory refreshed — {CachedEntriesLoaded} neighbor-cache entries, " +
              $"{KnownDeviceCount} known devices; {ProbeRequestsSent} paced ARP discovery requests sent across the selected local IPv4 segment.";
}
