namespace Lantern.App.Services;

public sealed record DiscoveryRefreshResult(
    int CachedEntriesLoaded,
    int KnownDeviceCount,
    int ProbeRequestsSent = 0,
    string? ProbeWarning = null)
{
    public string StatusMessage => ProbeWarning is null
        ? $"Device inventory refreshed — {CachedEntriesLoaded} cached entries, " +
          $"{KnownDeviceCount} known devices; {ProbeRequestsSent} paced presence probes sent " +
          "to previously known IP addresses."
        : $"Device inventory refreshed — {CachedEntriesLoaded} cached entries, " +
          $"{KnownDeviceCount} known devices. Live presence checks were unavailable: {ProbeWarning}";
}
