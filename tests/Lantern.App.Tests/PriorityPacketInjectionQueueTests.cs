using Lantern.App.Services;
using Xunit;

namespace Lantern.App.Tests;

public sealed class PriorityPacketInjectionQueueTests
{
    [Fact]
    public async Task RunAsync_SendsPriorityFramesBeforeQueuedForwardingFrames()
    {
        var queue = new PriorityPacketInjectionQueue(maximumForwardingQueueBytes: 32);
        var forwarded = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var sent = new List<byte>();
        using var cancellation = new CancellationTokenSource();

        Assert.True(queue.TryEnqueueForwarding(
            [new byte[] { 0x10 }],
            () => forwarded.TrySetResult()));
        var prioritySent = queue.SendPriorityAsync([0x01]);

        var runTask = queue.RunAsync(
            frame => sent.Add(frame[0]),
            () => true,
            onRetry: null,
            (_, _) => { },
            cancellation.Token);

        await prioritySent;
        await forwarded.Task.WaitAsync(TimeSpan.FromSeconds(2));
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => runTask);

        Assert.Equal([0x01, 0x10], sent);
    }

    [Fact]
    public void TryEnqueueForwarding_RejectsBatchesThatExceedByteBudget()
    {
        var queue = new PriorityPacketInjectionQueue(maximumForwardingQueueBytes: 4);

        Assert.True(queue.TryEnqueueForwarding([new byte[] { 1, 2, 3 }]));
        Assert.Equal(3, queue.ForwardingQueueBytes);
        Assert.False(queue.TryEnqueueForwarding([new byte[] { 4, 5 }]));
        Assert.Equal(3, queue.ForwardingQueueBytes);
    }

    [Fact]
    public async Task RunAsync_RetriesIndividualFramesBeforeReportingFailure()
    {
        var queue = new PriorityPacketInjectionQueue(maximumForwardingQueueBytes: 32);
        var attempts = 0;
        var retries = new List<int>();
        using var cancellation = new CancellationTokenSource();

        var prioritySent = queue.SendPriorityAsync([0x55]);
        var runTask = queue.RunAsync(
            _ =>
            {
                attempts++;
                if (attempts < 3)
                {
                    throw new IOException("Temporary injection failure.");
                }
            },
            () => true,
            (_, attempt, _) => retries.Add(attempt),
            (_, _) => { },
            cancellation.Token);

        await prioritySent;
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => runTask);

        Assert.Equal(3, attempts);
        Assert.Equal([2, 3], retries);
    }

    [Fact]
    public async Task RunAsync_ReportsUnrecoverablePrioritySendFailureToCaller()
    {
        var queue = new PriorityPacketInjectionQueue(maximumForwardingQueueBytes: 32);
        var failureReported = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        using var cancellation = new CancellationTokenSource();

        var prioritySent = queue.SendPriorityAsync([0x55]);
        var runTask = queue.RunAsync(
            _ => throw new IOException("Npcap send failed."),
            () => true,
            onRetry: null,
            (_, _) => failureReported.TrySetResult(),
            cancellation.Token);

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            () => prioritySent);
        await failureReported.Task.WaitAsync(TimeSpan.FromSeconds(2));
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => runTask);

        Assert.Contains("after 3 attempts", exception.Message);
    }
    [Fact]
    public async Task RunAsync_PriorityArpTrafficPreemptsAForwardingBacklog()
    {
        var queue = new PriorityPacketInjectionQueue(maximumForwardingQueueBytes: 32);
        var firstForwardStarted = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var allForwarded = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        using var allowFirstSend = new ManualResetEventSlim(false);
        using var cancellation = new CancellationTokenSource();
        var sent = new System.Collections.Concurrent.ConcurrentQueue<byte>();
        var forwardedCount = 0;

        Assert.True(queue.TryEnqueueForwarding([new byte[] { 0x10 }]));
        Assert.True(queue.TryEnqueueForwarding([new byte[] { 0x11 }]));
        Assert.True(queue.TryEnqueueForwarding(
            [new byte[] { 0x12 }],
            () => allForwarded.TrySetResult()));

        var runTask = Task.Run(async () => await queue.RunAsync(
            frame =>
            {
                if (frame[0] == 0x10)
                {
                    firstForwardStarted.TrySetResult();
                    allowFirstSend.Wait();
                }

                sent.Enqueue(frame[0]);
                if (frame[0] is 0x10 or 0x11 or 0x12)
                {
                    Interlocked.Increment(ref forwardedCount);
                }
            },
            () => true,
            onRetry: null,
            (_, _) => { },
            cancellation.Token));

        try
        {
            await firstForwardStarted.Task.WaitAsync(TimeSpan.FromSeconds(2));
            var prioritySent = queue.SendPriorityAsync([0x01]);
            allowFirstSend.Set();

            await prioritySent.WaitAsync(TimeSpan.FromSeconds(2));
            await allForwarded.Task.WaitAsync(TimeSpan.FromSeconds(2));
            Assert.Equal(3, Volatile.Read(ref forwardedCount));
            Assert.Equal(new byte[] { 0x10, 0x01, 0x11, 0x12 }, sent.ToArray());
        }
        finally
        {
            allowFirstSend.Set();
            cancellation.Cancel();
        }

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => runTask);
    }

}
