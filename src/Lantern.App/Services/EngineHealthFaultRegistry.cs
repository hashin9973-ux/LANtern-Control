using System.Collections.Concurrent;

namespace Lantern.App.Services;

/// <summary>
/// Tracks independent, recoverable packet-health faults. Clearing a queue
/// overload must not accidentally clear a simultaneous Npcap capture-drop or
/// diagnostic fault.
/// </summary>
public sealed class EngineHealthFaultRegistry
{
    private readonly ConcurrentDictionary<string, string> faults =
        new(StringComparer.OrdinalIgnoreCase);

    public bool IsHealthy => faults.IsEmpty;

    public string? PrimaryReason => faults
        .OrderBy(pair => pair.Key, StringComparer.Ordinal)
        .Select(pair => pair.Value)
        .FirstOrDefault();

    public bool TrySet(string key, string reason)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);
        ArgumentException.ThrowIfNullOrWhiteSpace(reason);
        return faults.TryAdd(key, reason);
    }

    public bool TryClear(string key) => faults.TryRemove(key, out _);

    public void Clear() => faults.Clear();
}
