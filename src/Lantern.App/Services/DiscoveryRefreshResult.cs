namespace Lantern.App.Services;

public sealed record DiscoveryRefreshResult(
    int CachedEntriesLoaded,
    int KnownDeviceCount,
    int ProbeRequestsSent = 0,
    string? ProbeWarning = null)
{
    public string StatusMessage => ProbeWarning is not null
        ? $"Device inventory refreshed — {CachedEntriesLoaded} cached entries, " +
          $"{KnownDeviceCount} known devices. Live presence checks were unavailable: {ProbeWarning}"
        : ProbeRequestsSent == 0
            ? $"Device inventory refreshed — {CachedEntriesLoaded} cached entries, " +
              $"{KnownDeviceCount} known devices. No presence checks were due; checks are rate-limited."
            : $"Device inventory refreshed — {CachedEntriesLoaded} cached entries, " +
              $"{KnownDeviceCount} known devices; {ProbeRequestsSent} paced presence probes sent " +
              "to previously known IP addresses.";
}
