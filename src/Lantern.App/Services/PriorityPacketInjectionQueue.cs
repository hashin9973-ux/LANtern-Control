using System.Collections.Concurrent;
using System.Threading.Channels;

namespace Lantern.App.Services;

/// <summary>
/// Serializes packet injection on the selected Npcap handle while giving ARP
/// enforcement work priority over forwarded traffic. The forwarded queue is
/// byte-bounded so sustained overload cannot turn into unbounded memory growth.
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
    private long forwardingQueueBytes;

    public PriorityPacketInjectionQueue(long maximumForwardingQueueBytes)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maximumForwardingQueueBytes);
        this.maximumForwardingQueueBytes = maximumForwardingQueueBytes;
    }

    public long ForwardingQueueBytes => Interlocked.Read(ref forwardingQueueBytes);

    public long MaximumForwardingQueueBytes => maximumForwardingQueueBytes;

    public Task SendPriorityAsync(byte[] frame, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(frame);
        cancellationToken.ThrowIfCancellationRequested();

        var completion = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        priorityQueue.Enqueue(new PacketWorkItem(
            [frame],
            IsPriority: true,
            QueuedBytes: frame.LongLength,
            Completion: completion,
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

        var ownedFrames = frames.ToArray();
        var batchBytes = ownedFrames.Sum(static frame => (long)frame.LongLength);
        var currentBytes = Interlocked.Add(ref forwardingQueueBytes, batchBytes);
        if (currentBytes > maximumForwardingQueueBytes)
        {
            Interlocked.Add(ref forwardingQueueBytes, -batchBytes);
            return false;
        }

        forwardingQueue.Enqueue(new PacketWorkItem(
            ownedFrames,
            IsPriority: false,
            QueuedBytes: batchBytes,
            Completion: null,
            OnSent: onSent));
        signal.Writer.TryWrite(true);
        return true;
    }

    public async Task RunAsync(
        Action<byte[]> sendPacket,
        Action<string, int, Exception>? onRetry,
        Action<string, Exception> onFailure,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(sendPacket);
        ArgumentNullException.ThrowIfNull(onFailure);

        try
        {
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();

                PacketWorkItem? workItem = null;
                if (priorityQueue.TryDequeue(out var priorityItem))
                {
                    workItem = priorityItem;
                }
                else if (forwardingQueue.TryDequeue(out var forwardingItem))
                {
                    workItem = forwardingItem;
                    Interlocked.Add(ref forwardingQueueBytes, -forwardingItem.QueuedBytes);
                }

                if (workItem is null)
                {
                    await signal.Reader.ReadAsync(cancellationToken);
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
            while (priorityQueue.TryDequeue(out var priorityItem))
            {
                priorityItem.Completion?.TrySetCanceled(cancellationToken);
            }

            while (forwardingQueue.TryDequeue(out var forwardingItem))
            {
                Interlocked.Add(ref forwardingQueueBytes, -forwardingItem.QueuedBytes);
                forwardingItem.Completion?.TrySetCanceled(cancellationToken);
            }
        }
    }

    private sealed record PacketWorkItem(
        IReadOnlyList<byte[]> Frames,
        bool IsPriority,
        long QueuedBytes,
        TaskCompletionSource? Completion,
        Action? OnSent);
}
