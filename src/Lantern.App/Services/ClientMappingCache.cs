using System.Collections.Concurrent;
using System.Net;
using System.Net.NetworkInformation;

namespace Lantern.App.Services;

public sealed class ClientMappingCache
{
    private readonly object sync = new();

    public ConcurrentDictionary<IPAddress, PhysicalAddress> Mappings { get; } = new();

    public void BeginAdapter(string id)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(id);
        lock (sync)
        {
            Mappings.Clear();
        }
    }

    public IReadOnlyList<IPAddress> RemoveByMac(PhysicalAddress macAddress)
    {
        ArgumentNullException.ThrowIfNull(macAddress);
        lock (sync)
        {
            var addresses = Mappings
                .Where(pair => pair.Value.Equals(macAddress))
                .Select(pair => pair.Key)
                .ToArray();
            foreach (var address in addresses)
            {
                Mappings.TryRemove(address, out _);
            }

            return addresses;
        }
    }

    public bool Upsert(IPAddress address, PhysicalAddress macAddress)
    {
        ArgumentNullException.ThrowIfNull(address);
        ArgumentNullException.ThrowIfNull(macAddress);
        lock (sync)
        {
            var changed = !Mappings.TryGetValue(address, out var previous) ||
                          !previous.Equals(macAddress);
            foreach (var staleAddress in Mappings
                         .Where(pair =>
                             pair.Value.Equals(macAddress) &&
                             !pair.Key.Equals(address))
                         .Select(pair => pair.Key)
                         .ToArray())
            {
                Mappings.TryRemove(staleAddress, out _);
            }

            Mappings[address] = macAddress;
            return changed;
        }
    }
}
