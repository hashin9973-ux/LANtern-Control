using System.Net;
using Lantern.Core.Devices;
using Lantern.Core.Networking;

namespace Lantern.App.Services;

/// <summary>
/// Selects known addresses for low-rate presence checks and, separately,
/// candidate addresses for an explicitly requested local-network discovery pass.
/// </summary>
public static class DeviceProbePolicy
{
    public static TimeSpan ProbeInterval { get; } = TimeSpan.FromSeconds(60);

    public const int MaxTargetsPerBatch = 100;

    public static TimeSpan MinimumTimeBetweenProbes { get; } = TimeSpan.FromSeconds(60);

    public static TimeSpan MinimumAgeBeforeProbe { get; } = TimeSpan.FromSeconds(45);

    public static TimeSpan RequestSpacing { get; } = TimeSpan.FromMilliseconds(150);

    public static TimeSpan DiscoveryRequestSpacing { get; } = TimeSpan.FromMilliseconds(200);

    public static TimeSpan DiscoveryInterval { get; } = TimeSpan.FromSeconds(60);

    public const int MaxDiscoveryTargetsPerScan = 253;

    public static TimeSpan ReplyWindow { get; } = TimeSpan.FromMilliseconds(900);

    /// <summary>
    /// Selects only previously observed host addresses for automatic presence checks.
    /// This method never enumerates unknown addresses across the subnet.
    /// </summary>
    public static IReadOnlyList<IPAddress> GetTargets(
        IEnumerable<DeviceSnapshot> inventory,
        AdapterProfile adapter,
        DateTimeOffset now,
        bool force,
        IReadOnlyDictionary<IPAddress, DateTimeOffset>? lastProbeAt = null)
    {
        ArgumentNullException.ThrowIfNull(inventory);
        ArgumentNullException.ThrowIfNull(adapter);

        var localHosts = IPv4DiscoveryRange
            .EnumerateHosts(adapter.LocalAddress, adapter.PrefixLength)
            .ToHashSet();

        return inventory
            .Where(device =>
                !device.IpAddress.Equals(adapter.LocalAddress) &&
                !device.IpAddress.Equals(adapter.GatewayAddress) &&
                localHosts.Contains(device.IpAddress))
            .Where(device =>
                lastProbeAt is null ||
                !lastProbeAt.TryGetValue(device.IpAddress, out var previousProbe) ||
                (now >= previousProbe && now - previousProbe >= MinimumTimeBetweenProbes))
            .Where(device =>
                force ||
                device.LastSeen == DateTimeOffset.MinValue ||
                (now >= device.LastSeen && now - device.LastSeen >= MinimumAgeBeforeProbe))
            .DistinctBy(device => device.IpAddress)
            .OrderBy(device =>
                lastProbeAt is not null &&
                lastProbeAt.TryGetValue(device.IpAddress, out var previousProbe)
                    ? previousProbe
                    : DateTimeOffset.MinValue)
            .ThenBy(device => ToUInt32(device.IpAddress))
            .Take(MaxTargetsPerBatch)
            .Select(device => device.IpAddress)
            .ToArray();
    }

    /// <summary>
    /// Returns a bounded, one-pass list for a user-requested discovery scan.
    /// Larger networks are already constrained to the local /24 by
    /// IPv4DiscoveryRange. The controller and gateway are never probed.
    /// </summary>
    public static IReadOnlyList<IPAddress> GetDiscoveryTargets(AdapterProfile adapter)
    {
        ArgumentNullException.ThrowIfNull(adapter);

        return IPv4DiscoveryRange
            .EnumerateHosts(adapter.LocalAddress, adapter.PrefixLength)
            .Where(address =>
                !address.Equals(adapter.LocalAddress) &&
                !address.Equals(adapter.GatewayAddress))
            .Distinct()
            .OrderBy(ToUInt32)
            .Take(MaxDiscoveryTargetsPerScan)
            .ToArray();
    }

    private static uint ToUInt32(IPAddress address)
    {
        var bytes = address.GetAddressBytes();
        return ((uint)bytes[0] << 24) |
               ((uint)bytes[1] << 16) |
               ((uint)bytes[2] << 8) |
               bytes[3];
    }
}
