using System.Diagnostics;

namespace Lantern.App.Services;

/// <summary>
/// Provides a serialized, short-lived cache over fresh Native Wi-Fi scans.
/// The cache prevents a user-configured five-second rule poll from launching
/// a disruptive radio scan on every tick.
/// </summary>
public sealed class WindowsWifiNetworkMonitor
{
    private static readonly TimeSpan MinimumFreshScanInterval = TimeSpan.FromSeconds(10);

    private readonly IWindowsWifiScanSource scanSource;
    private readonly TimeSpan cacheDuration;
    private readonly SemaphoreSlim scanGate = new(1, 1);
    private IReadOnlyList<string>? cachedSsids;
    private long cachedAtTimestamp;

    public WindowsWifiNetworkMonitor()
        : this(new WindowsWlanScanSource(), MinimumFreshScanInterval)
    {
    }

    internal WindowsWifiNetworkMonitor(
        IWindowsWifiScanSource scanSource,
        TimeSpan cacheDuration)
    {
        ArgumentNullException.ThrowIfNull(scanSource);
        if (cacheDuration <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(cacheDuration));
        }

        this.scanSource = scanSource;
        this.cacheDuration = cacheDuration;
    }

    public async Task<IReadOnlyList<string>> GetVisibleSsidsAsync(
        CancellationToken cancellationToken = default)
    {
        await scanGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (cachedSsids is not null &&
                Stopwatch.GetElapsedTime(cachedAtTimestamp) < cacheDuration)
            {
                return cachedSsids;
            }

            var scannedSsids = await scanSource
                .ScanVisibleSsidsAsync(cancellationToken)
                .ConfigureAwait(false);

            var snapshot = scannedSsids
                .Where(ssid => !string.IsNullOrWhiteSpace(ssid))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(ssid => ssid, StringComparer.OrdinalIgnoreCase)
                .ToArray();

            cachedSsids = snapshot;
            cachedAtTimestamp = Stopwatch.GetTimestamp();
            return snapshot;
        }
        finally
        {
            scanGate.Release();
        }
    }
}
