namespace Lantern.App.Services;

public sealed record DiscoveryRefreshResult(
    int CachedEntriesLoaded,
    int KnownDeviceCount)
{
    public string StatusMessage =>
        $"Device inventory refreshed — {CachedEntriesLoaded} cached entries, " +
        $"{KnownDeviceCount} known devices. No scan probes were sent.";
}
