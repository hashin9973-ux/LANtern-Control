namespace Lantern.App.Services;

/// <summary>
/// Separates startup readiness from transient health. A degraded engine can
/// become healthy again after every prerequisite recovers; the reported-health
/// flag must not itself be a prerequisite for recovery.
/// </summary>
public sealed class EngineHealthState
{
    private int started;
    private int healthy;

    public bool IsHealthy =>
        Volatile.Read(ref started) == 1 &&
        Volatile.Read(ref healthy) == 1;

    public void BeginStart()
    {
        Volatile.Write(ref started, 0);
        Volatile.Write(ref healthy, 0);
    }

    public void CompleteStart(bool prerequisitesSatisfied)
    {
        Volatile.Write(ref healthy, prerequisitesSatisfied ? 1 : 0);
        Volatile.Write(ref started, 1);
    }

    public bool Refresh(bool prerequisitesSatisfied)
    {
        if (Volatile.Read(ref started) != 1)
        {
            return false;
        }

        var next = prerequisitesSatisfied ? 1 : 0;
        return Interlocked.Exchange(ref healthy, next) != next;
    }

    public void MarkDegraded() => Interlocked.Exchange(ref healthy, 0);

    public void Stop() => BeginStart();
}
