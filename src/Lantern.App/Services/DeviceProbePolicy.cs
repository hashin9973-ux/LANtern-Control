using System.Net;
using Lantern.Core.Devices;
using Lantern.Core.Networking;

namespace Lantern.App.Services;

/// <summary>
/// Selects only previously observed host addresses for low-rate presence checks.
/// It never enumerates or probes unknown addresses across the subnet.
/// </summary>
public static class DeviceProbePolicy
{
    public static TimeSpan ProbeInterval { get; } = TimeSpan.FromSeconds(60);

    public static TimeSpan MinimumTimeBetweenProbes { get; } = TimeSpan.FromSeconds(60);

    public static TimeSpan MinimumAgeBeforeProbe { get; } = TimeSpan.FromSeconds(45);

    public static TimeSpan RequestSpacing { get; } = TimeSpan.FromMilliseconds(150);

    public static TimeSpan ReplyWindow { get; } = TimeSpan.FromMilliseconds(900);

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
            .Select(device => device.IpAddress)
            .Distinct()
            .OrderBy(ToUInt32)
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
