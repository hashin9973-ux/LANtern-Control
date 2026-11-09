namespace Lantern.App.Services;

/// <summary>
/// Reports success only after every packet in a logical batch was accepted.
/// A single failed packet permanently marks that batch failed.
/// </summary>
public sealed class PacketBatchCompletion
{
    private readonly object sync = new();
    private readonly Action onCompleted;
    private readonly Action onFailed;
    private int remainingPackets;
    private bool completed;

    public PacketBatchCompletion(int packetCount, Action onCompleted, Action onFailed)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(packetCount);
        ArgumentNullException.ThrowIfNull(onCompleted);
        ArgumentNullException.ThrowIfNull(onFailed);

        remainingPackets = packetCount;
        this.onCompleted = onCompleted;
        this.onFailed = onFailed;
    }

    public void MarkPacketSent()
    {
        Action? callback = null;
        lock (sync)
        {
            if (completed)
            {
                return;
            }

            remainingPackets--;
            if (remainingPackets < 0)
            {
                throw new InvalidOperationException("More packet completions were reported than the batch contains.");
            }

            if (remainingPackets == 0)
            {
                completed = true;
                callback = onCompleted;
            }
        }

        callback?.Invoke();
    }

    public void MarkPacketFailed()
    {
        Action? callback = null;
        lock (sync)
        {
            if (!completed)
            {
                completed = true;
                callback = onFailed;
            }
        }

        callback?.Invoke();
    }
}