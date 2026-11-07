using System.Net;
using System.Net.NetworkInformation;
using Lantern.Core.Networking;

namespace Lantern.App.Services;

public sealed record ArpIdentityObservation(bool IsConflict, string? Warning);

/// <summary>
/// Correlates passive ARP sender claims to identify possible duplicate-IP or
/// cloned-MAC conditions. It never sends packets or changes neighbor mappings.
/// </summary>
public sealed class ArpIdentityMonitor
{
    private static readonly TimeSpan CorrelationWindow = TimeSpan.FromMinutes(2);
    private static readonly TimeSpan AlertRepeatWindow = TimeSpan.FromSeconds(30);
    private readonly object sync = new();
    private readonly Dictionary<IPAddress, IpClaim> claimsByIp = [];
    private readonly Dictionary<string, MacClaim> claimsByMac =
        new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, DateTimeOffset> lastAlerts =
        new(StringComparer.Ordinal);

    public ArpIdentityObservation Observe(
        ArpFrameInfo arp,
        IPAddress controllerAddress,
        PhysicalAddress controllerMac,
        DateTimeOffset observedAt)
    {
        ArgumentNullException.ThrowIfNull(controllerAddress);
        ArgumentNullException.ThrowIfNull(controllerMac);

        var macKey = arp.SenderMac.ToString();
        var conflictKey = string.Empty;
        var warning = string.Empty;

        lock (sync)
        {
            PruneExpiredClaims(observedAt);

            if (arp.SenderIp.Equals(IPAddress.Any) ||
                IsZeroOrBroadcast(arp.SenderMac))
            {
                return new ArpIdentityObservation(false, null);
            }

            if (!arp.HasConsistentSender)
            {
                conflictKey = $"ethernet-arp-mismatch|{arp.SenderIp}|{macKey}";
                warning = "the Ethernet source MAC differs from the ARP sender MAC";
            }
            else if (arp.SenderMac.Equals(controllerMac) &&
                     !arp.SenderIp.Equals(controllerAddress))
            {
                conflictKey = $"controller-mac-claimed|{arp.SenderIp}|{macKey}";
                warning = $"another host is claiming this computer's MAC address at {arp.SenderIp}";
            }
            else if (arp.SenderIp.Equals(controllerAddress) &&
                     !arp.SenderMac.Equals(controllerMac))
            {
                conflictKey = $"controller-ip-claimed|{arp.SenderIp}|{macKey}";
                warning = $"another MAC address is claiming this computer's IP address {arp.SenderIp}";
            }
            else if (claimsByIp.TryGetValue(arp.SenderIp, out var previousIpClaim) &&
                     !previousIpClaim.MacAddress.Equals(arp.SenderMac) &&
                     IsRecent(previousIpClaim.SeenAt, observedAt))
            {
                conflictKey = $"ip-moved|{arp.SenderIp}|{macKey}";
                warning = $"{arp.SenderIp} was recently associated with MAC " +
                    $"{previousIpClaim.MacAddress}; a different MAC is now claiming it";
            }
            else if (claimsByMac.TryGetValue(macKey, out var previousMacClaim) &&
                     !previousMacClaim.IpAddress.Equals(arp.SenderIp) &&
                     IsRecent(previousMacClaim.SeenAt, observedAt))
            {
                conflictKey = $"mac-moved|{macKey}|{arp.SenderIp}";
                warning = $"MAC {macKey} is claiming both {previousMacClaim.IpAddress} " +
                    $"and {arp.SenderIp}";
            }

            if (warning.Length == 0)
            {
                claimsByIp[arp.SenderIp] = new IpClaim(arp.SenderMac, observedAt);
                claimsByMac[macKey] = new MacClaim(arp.SenderIp, observedAt);
                return new ArpIdentityObservation(false, null);
            }

            if (lastAlerts.TryGetValue(conflictKey, out var lastAlertAt) &&
                IsRecent(lastAlertAt, observedAt) &&
                observedAt - lastAlertAt < AlertRepeatWindow)
            {
                return new ArpIdentityObservation(true, null);
            }

            lastAlerts[conflictKey] = observedAt;
            return new ArpIdentityObservation(
                true,
                $"Potential ARP identity conflict: {warning}. " +
                "This is a warning, not proof of spoofing; proxy ARP, address changes, " +
                "or multi-address devices can produce similar signals.");
        }
    }

    private void PruneExpiredClaims(DateTimeOffset now)
    {
        foreach (var address in claimsByIp
                     .Where(pair => !IsRecent(pair.Value.SeenAt, now))
                     .Select(pair => pair.Key)
                     .ToArray())
        {
            claimsByIp.Remove(address);
        }

        foreach (var mac in claimsByMac
                     .Where(pair => !IsRecent(pair.Value.SeenAt, now))
                     .Select(pair => pair.Key)
                     .ToArray())
        {
            claimsByMac.Remove(mac);
        }

        foreach (var key in lastAlerts
                     .Where(pair => !IsRecent(pair.Value, now))
                     .Select(pair => pair.Key)
                     .ToArray())
        {
            lastAlerts.Remove(key);
        }
    }

    private static bool IsRecent(DateTimeOffset seenAt, DateTimeOffset now) =>
        now >= seenAt && now - seenAt <= CorrelationWindow;

    private static bool IsZeroOrBroadcast(PhysicalAddress address)
    {
        var bytes = address.GetAddressBytes();
        return bytes.Length != 6 ||
               bytes.All(value => value == 0) ||
               bytes.All(value => value == byte.MaxValue) ||
               (bytes[0] & 1) != 0;
    }

    private sealed record IpClaim(PhysicalAddress MacAddress, DateTimeOffset SeenAt);

    private sealed record MacClaim(IPAddress IpAddress, DateTimeOffset SeenAt);
}
