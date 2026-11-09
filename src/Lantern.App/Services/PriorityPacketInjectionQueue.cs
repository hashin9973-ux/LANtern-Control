using System.Collections.Concurrent;
using System.Threading.Channels;

namespace Lantern.App.Services;

/// <summary>
/// Serializes injection through one Npcap handle. Control/ARP frames have
/// priority over forwarded frames. Both queues are byte-bounded; forwarded
/// traffic is rejected rather than allowing unbounded memory growth.
/// </summary>
public sealed class PriorityPacketInjectionQueue
{
    private readonly ConcurrentQueue<PacketWorkItem> priorityQueue = new();
    private readonly ConcurrentQueue<PacketWorkItem> forwardingQueue = new();
    private readonly Channel<bool> signal = Channel.CreateBounded<bool>(
        new BoundedChannelOptions(1)
        {
            SingleReader = true,
            SingleWriter = false,
            FullMode = BoundedChannelFullMode.DropWrite,
        });
    private readonly long maximumForwardingQueueBytes;
    private readonly long maximumPriorityQueueBytes;
    private long forwardingQueueBytes;
    private long priorityQueueBytes;

    public PriorityPacketInjectionQueue(
        long maximumForwardingQueueBytes,
        long maximumPriorityQueueBytes = 1024 * 1024)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maximumForwardingQueueBytes);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maximumPriorityQueueBytes);
        this.maximumForwardingQueueBytes = maximumForwardingQueueBytes;
        this.maximumPriorityQueueBytes = maximumPriorityQueueBytes;
    }

    public long ForwardingQueueBytes => Interlocked.Read(ref forwardingQueueBytes);

    public long PriorityQueueBytes => Interlocked.Read(ref priorityQueueBytes);

    public long MaximumForwardingQueueBytes => maximumForwardingQueueBytes;

    public long MaximumPriorityQueueBytes => maximumPriorityQueueBytes;

    /// <summary>
    /// Enqueues an ARP/control frame without blocking the caller (including
    /// SharpPcap's packet-arrival callback). A full priority queue is fatal:
    /// the caller must not pretend enforcement succeeded.
    /// </summary>
    public void EnqueuePriority(byte[] frame)
    {
        ArgumentNullException.ThrowIfNull(frame);
        if (frame.Length == 0)
        {
            throw new ArgumentException("An injection frame cannot be empty.", nameof(frame));
        }

        if (!TryReserve(ref priorityQueueBytes, maximumPriorityQueueBytes, frame.LongLength))
        {
            throw new InvalidOperationException(
                $"The ARP/control injection queue exceeded its {maximumPriorityQueueBytes}-byte limit.");
        }

        priorityQueue.Enqueue(new PacketWorkItem(
            [frame],
            IsPriority: true,
            QueuedBytes: frame.LongLength,
            Completion: null,
            CancellationToken: CancellationToken.None,
            OnSent: null));
        signal.Writer.TryWrite(true);
    }

    /// <summary>
    /// Enqueues and awaits a priority frame, used during startup and network restoration.
    /// </summary>
    public Task SendPriorityAsync(
        byte[] frame,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(frame);
        if (frame.Length == 0)
        {
            throw new ArgumentException("An injection frame cannot be empty.", nameof(frame));
        }

        cancellationToken.ThrowIfCancellationRequested();
        if (!TryReserve(ref priorityQueueBytes, maximumPriorityQueueBytes, frame.LongLength))
        {
            throw new InvalidOperationException(
                $"The ARP/control injection queue exceeded its {maximumPriorityQueueBytes}-byte limit.");
        }

        var completion = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        priorityQueue.Enqueue(new PacketWorkItem(
            [frame],
            IsPriority: true,
            QueuedBytes: frame.LongLength,
            Completion: completion,
            CancellationToken: cancellationToken,
            OnSent: null));
        signal.Writer.TryWrite(true);
        return completion.Task.WaitAsync(cancellationToken);
    }

    public bool TryEnqueueForwarding(
        IReadOnlyList<byte[]> frames,
        Action? onSent = null)
    {
        ArgumentNullException.ThrowIfNull(frames);
        if (frames.Count == 0 || frames.Any(static frame => frame is null || frame.Length == 0))
        {
            return false;
        }

        var batchBytes = frames.Sum(static frame => (long)frame.LongLength);
        if (!TryReserve(ref forwardingQueueBytes, maximumForwardingQueueBytes, batchBytes))
        {
            return false;
        }

        forwardingQueue.Enqueue(new PacketWorkItem(
            frames.ToArray(),
            IsPriority: false,
            QueuedBytes: batchBytes,
            Completion: null,
            CancellationToken: CancellationToken.None,
            OnSent: onSent));
        signal.Writer.TryWrite(true);
        return true;
    }

    public async Task RunAsync(
        Action<byte[]> sendPacket,
        Func<bool> maySendForwardedPackets,
        Action<string, int, Exception>? onRetry,
        Action<string, Exception> onFailure,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(sendPacket);
        ArgumentNullException.ThrowIfNull(maySendForwardedPackets);
        ArgumentNullException.ThrowIfNull(onFailure);

        try
        {
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();

                if (!TryDequeue(out var workItem))
                {
                    await signal.Reader.ReadAsync(cancellationToken);
                    continue;
                }

                if (workItem.CancellationToken.IsCancellationRequested)
                {
                    workItem.Completion?.TrySetCanceled(workItem.CancellationToken);
                    continue;
                }

                if (!workItem.IsPriority && !maySendForwardedPackets())
                {
                    continue;
                }

                try
                {
                    foreach (var frame in workItem.Frames)
                    {
                        await ArpEnforcementRetry.ExecuteAsync(
                            () => sendPacket(frame),
                            cancellationToken,
                            (attempt, exception) => onRetry?.Invoke(
                                workItem.IsPriority ? "ARP enforcement" : "forwarding",
                                attempt,
                                exception));
                    }

                    workItem.OnSent?.Invoke();
                    workItem.Completion?.TrySetResult();
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    workItem.Completion?.TrySetCanceled(cancellationToken);
                    throw;
                }
                catch (Exception exception)
                {
                    workItem.Completion?.TrySetException(exception);
                    onFailure(
                        workItem.IsPriority ? "ARP packet injection failed" : "Forwarding packet injection failed",
                        exception);
                }
            }
        }
        finally
        {
            while (TryDequeue(out var workItem))
            {
                workItem.Completion?.TrySetCanceled(cancellationToken);
            }
        }
    }

    private bool TryDequeue(out PacketWorkItem workItem)
    {
        if (priorityQueue.TryDequeue(out workItem!))
        {
            Interlocked.Add(ref priorityQueueBytes, -workItem.QueuedBytes);
            return true;
        }

        if (forwardingQueue.TryDequeue(out workItem!))
        {
            Interlocked.Add(ref forwardingQueueBytes, -workItem.QueuedBytes);
            return true;
        }

        workItem = null!;
        return false;
    }

    private static bool TryReserve(ref long currentBytes, long maximumBytes, long requestedBytes)
    {
        while (true)
        {
            var current = Interlocked.Read(ref currentBytes);
            if (requestedBytes > maximumBytes - current)
            {
                return false;
            }

            if (Interlocked.CompareExchange(
                    ref currentBytes,
                    current + requestedBytes,
                    current) == current)
            {
                return true;
            }
        }
    }

    private sealed record PacketWorkItem(
        IReadOnlyList<byte[]> Frames,
        bool IsPriority,
        long QueuedBytes,
        TaskCompletionSource? Completion,
        CancellationToken CancellationToken,
        Action? OnSent);
}
