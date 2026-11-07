using System.Collections.Concurrent;
using System.Net;
using System.Net.NetworkInformation;
using Lantern.Core.Control;

namespace Lantern.Core.Devices;

public sealed class DeviceRegistry
{
    private readonly ConcurrentDictionary<string, DeviceRecord> devices =
        new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<IPAddress, DeviceRecord> ipOnlyDevices = new();
    private readonly object snapshotSync = new();
    private DateTimeOffset lastSnapshot;

    public DeviceRegistry(DateTimeOffset? startedAt = null)
    {
        lastSnapshot = startedAt ?? DateTimeOffset.UtcNow;
    }

    public void BeginSession()
    {
        devices.Clear();
        ipOnlyDevices.Clear();
        lock (snapshotSync)
        {
            lastSnapshot = DateTimeOffset.UtcNow;
        }
    }

    public void Observe(
        IPAddress ipAddress,
        PhysicalAddress macAddress,
        DateTimeOffset seenAt,
        string? hostName = null)
    {
        ArgumentNullException.ThrowIfNull(ipAddress);
        ArgumentNullException.ThrowIfNull(macAddress);
        ipOnlyDevices.TryRemove(ipAddress, out _);
        AddOrUpdate(ipAddress, macAddress, seenAt, hostName, refreshLastSeen: true);
    }

    /// <summary>
    /// Records a positively responding IPv4 host when no trustworthy MAC mapping
    /// was learned. These records are inventory-only and cannot be controlled.
    /// </summary>
    public void ObserveIpOnly(
        IPAddress ipAddress,
        DateTimeOffset seenAt,
        string? hostName = null)
    {
        ArgumentNullException.ThrowIfNull(ipAddress);
        if (ipAddress.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
        {
            throw new ArgumentException("IP-only inventory supports IPv4 addresses only.", nameof(ipAddress));
        }

        ipOnlyDevices.AddOrUpdate(
            ipAddress,
            _ => new DeviceRecord
            {
                MacAddress = PhysicalAddress.None,
                IpAddress = ipAddress,
                HostName = hostName,
                FirstSeen = seenAt,
                LastSeen = seenAt,
            },
            (_, existing) =>
            {
                existing.LastSeen = seenAt;
                if (!string.IsNullOrWhiteSpace(hostName))
                {
                    existing.HostName = hostName;
                }

                return existing;
            });
    }

    public void Remember(
        IPAddress ipAddress,
        PhysicalAddress macAddress,
        DateTimeOffset rememberedAt,
        string? hostName = null,
        DateTimeOffset? lastSeen = null) =>
        AddOrUpdate(
            ipAddress,
            macAddress,
            rememberedAt,
            hostName,
            refreshLastSeen: false,
            rememberedLastSeen: lastSeen);

    private void AddOrUpdate(
        IPAddress ipAddress,
        PhysicalAddress macAddress,
        DateTimeOffset timestamp,
        string? hostName,
        bool refreshLastSeen,
        DateTimeOffset? rememberedLastSeen = null)
    {
        ArgumentNullException.ThrowIfNull(ipAddress);
        ArgumentNullException.ThrowIfNull(macAddress);
        var key = TrafficPolicy.NormalizeMac(macAddress.ToString());
        devices.AddOrUpdate(
            key,
            _ => new DeviceRecord
            {
                MacAddress = macAddress,
                IpAddress = ipAddress,
                HostName = hostName,
                FirstSeen = timestamp,
                LastSeen = refreshLastSeen
                    ? timestamp
                    : rememberedLastSeen ?? DateTimeOffset.MinValue,
            },
            (_, existing) =>
            {
                existing.IpAddress = ipAddress;
                if (refreshLastSeen)
                {
                    existing.LastSeen = timestamp;
                }
                else if (rememberedLastSeen is { } lastSeen &&
                         (existing.LastSeen == DateTimeOffset.MinValue ||
                          lastSeen > existing.LastSeen))
                {
                    existing.LastSeen = lastSeen;
                }

                if (!string.IsNullOrWhiteSpace(hostName))
                {
                    existing.HostName = hostName;
                }

                return existing;
            });
    }

    public bool Remove(PhysicalAddress macAddress)
    {
        ArgumentNullException.ThrowIfNull(macAddress);
        var key = TrafficPolicy.NormalizeMac(macAddress.ToString());
        return devices.TryRemove(key, out _);
    }

    public bool RemoveIpOnly(IPAddress ipAddress)
    {
        ArgumentNullException.ThrowIfNull(ipAddress);
        return ipOnlyDevices.TryRemove(ipAddress, out _);
    }

    public void SetHostName(PhysicalAddress macAddress, string? hostName)
    {
        if (string.IsNullOrWhiteSpace(hostName))
        {
            return;
        }

        var key = TrafficPolicy.NormalizeMac(macAddress.ToString());
        if (devices.TryGetValue(key, out var record))
        {
            record.HostName = hostName;
        }
    }

    public void RecordTraffic(
        PhysicalAddress macAddress,
        TrafficDirection direction,
        int byteCount,
        DateTimeOffset? seenAt = null)
    {
        if (byteCount <= 0)
        {
            return;
        }

        var key = TrafficPolicy.NormalizeMac(macAddress.ToString());
        if (!devices.TryGetValue(key, out var record))
        {
            return;
        }

        record.LastSeen = seenAt ?? DateTimeOffset.UtcNow;

        if (direction == TrafficDirection.Download)
        {
            Interlocked.Add(ref record.DownloadBytes, byteCount);
        }
        else
        {
            Interlocked.Add(ref record.UploadBytes, byteCount);
        }
    }

    public void RecordTraffic(
        IPAddress ipAddress,
        PhysicalAddress macAddress,
        TrafficDirection direction,
        int byteCount,
        DateTimeOffset? seenAt = null)
    {
        ArgumentNullException.ThrowIfNull(ipAddress);
        ArgumentNullException.ThrowIfNull(macAddress);
        if (byteCount <= 0)
        {
            return;
        }

        var macKey = TrafficPolicy.NormalizeMac(macAddress.ToString());
        var endpointKey = $"{macKey}|{ipAddress}";
        if (!devices.TryGetValue(macKey, out var record) ||
            !record.IpAddress.Equals(ipAddress))
        {
            return;
        }

        record.LastSeen = seenAt ?? DateTimeOffset.UtcNow;
        if (direction == TrafficDirection.Download)
        {
            Interlocked.Add(ref record.DownloadBytes, byteCount);
        }
        else
        {
            Interlocked.Add(ref record.UploadBytes, byteCount);
        }
    }

    public IReadOnlyList<DeviceSnapshot> TakeSnapshot(DateTimeOffset now)
    {
        lock (snapshotSync)
        {
            var seconds = Math.Max(0.001, (now - lastSnapshot).TotalSeconds);
            lastSnapshot = now;
            var snapshots = new List<DeviceSnapshot>(devices.Count + ipOnlyDevices.Count);
            foreach (var record in devices.Values.Concat(ipOnlyDevices.Values))
            {
                var download = Interlocked.Exchange(ref record.DownloadBytes, 0);
                var upload = Interlocked.Exchange(ref record.UploadBytes, 0);
                snapshots.Add(
                    new DeviceSnapshot(
                        record.MacAddress,
                        record.IpAddress,
                        record.HostName,
                        record.FirstSeen,
                        record.LastSeen,
                        download / seconds,
                        upload / seconds));
            }

            return snapshots
                .OrderByDescending(device => device.TotalBytesPerSecond)
                .ThenBy(device => device.IpAddress.ToString(), StringComparer.Ordinal)
                .ToArray();
        }
    }

    public IReadOnlyList<DeviceSnapshot> Peek() =>
        devices.Values
            .Concat(ipOnlyDevices.Values)
            .Select(
                record => new DeviceSnapshot(
                    record.MacAddress,
                    record.IpAddress,
                    record.HostName,
                    record.FirstSeen,
                    record.LastSeen,
                    0,
                    0))
            .ToArray();
}
