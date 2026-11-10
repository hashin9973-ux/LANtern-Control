namespace Lantern.App.Services;

/// <summary>
/// A paused client requires periodic successful ARP enforcement writes. An open
/// Npcap handle alone is not evidence that those writes are still succeeding.
/// </summary>
public static class ArpEnforcementHealthPolicy
{
    public static bool IsStale(
        bool hasInterceptionTargets,
        long lastSuccessfulInjectionUtcTicks,
        long nowUtcTicks,
        TimeSpan maximumSilence)
    {
        if (maximumSilence <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(
                nameof(maximumSilence),
                "Maximum ARP enforcement silence must be positive.");
        }

        if (!hasInterceptionTargets)
        {
            return false;
        }

        if (lastSuccessfulInjectionUtcTicks <= 0 ||
            nowUtcTicks < lastSuccessfulInjectionUtcTicks)
        {
            return true;
        }

        return nowUtcTicks - lastSuccessfulInjectionUtcTicks > maximumSilence.Ticks;
    }
}
