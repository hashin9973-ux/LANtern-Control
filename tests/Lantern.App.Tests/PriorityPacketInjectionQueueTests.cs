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
    public async Task RunAsync_ContinuesWithNextPriorityItemAfterAnUnrecoverableSendFailure()
    {
        var queue = new PriorityPacketInjectionQueue(maximumForwardingQueueBytes: 32);
        var failureReported = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var sent = new System.Collections.Concurrent.ConcurrentQueue<byte>();
        var failures = 0;
        using var cancellation = new CancellationTokenSource();

        var failedSend = queue.SendPriorityAsync([0x55]);
        var nextSend = queue.SendPriorityAsync([0x66]);
        var runTask = queue.RunAsync(
            frame =>
            {
                if (frame[0] == 0x55)
                {
                    throw new IOException("One Npcap send failed.");
                }

                sent.Enqueue(frame[0]);
            },
            () => true,
            onRetry: null,
            (_, _) =>
            {
                Interlocked.Increment(ref failures);
                failureReported.TrySetResult();
            },
            cancellation.Token);

        try
        {
            await Assert.ThrowsAsync<InvalidOperationException>(
                () => failedSend.WaitAsync(TimeSpan.FromSeconds(5)));
            await nextSend.WaitAsync(TimeSpan.FromSeconds(5));
            await failureReported.Task.WaitAsync(TimeSpan.FromSeconds(2));

            Assert.False(runTask.IsCompleted);
            Assert.Equal(new byte[] { 0x66 }, sent.ToArray());
            Assert.Equal(1, Volatile.Read(ref failures));
        }
        finally
        {
            cancellation.Cancel();
        }

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => runTask);
    }

    [Fact]
    public async Task RunAsync_FireAndForgetPriorityFailureMarksBatchFailedAndContinues()
    {
        var queue = new PriorityPacketInjectionQueue(maximumForwardingQueueBytes: 32);
        var batchCompleted = 0;
        var batchFailed = 0;
        var failureReported = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var nextItemSent = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        using var cancellation = new CancellationTokenSource();

        var batch = new PacketBatchCompletion(
            2,
            () => Interlocked.Increment(ref batchCompleted),
            () => Interlocked.Increment(ref batchFailed));

        queue.EnqueuePriority(
            [0x55],
            onSent: batch.MarkPacketSent,
            onFailed: batch.MarkPacketFailed);

        var runTask = queue.RunAsync(
            frame =>
            {
                if (frame[0] == 0x55)
                {
                    throw new IOException("One ARP work item failed.");
                }

                nextItemSent.TrySetResult();
            },
            () => true,
            onRetry: null,
            (_, _) => failureReported.TrySetResult(),
            cancellation.Token);

        try
        {
            var nextItem = queue.SendPriorityAsync([0x66]);
            await failureReported.Task.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.Equal(0, Volatile.Read(ref batchCompleted));
            Assert.Equal(1, Volatile.Read(ref batchFailed));

            await nextItem.WaitAsync(TimeSpan.FromSeconds(5));
            await nextItemSent.Task.WaitAsync(TimeSpan.FromSeconds(2));
            Assert.False(runTask.IsCompleted);
        }
        finally
        {
            cancellation.Cancel();
        }

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => runTask);
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

    [Fact]
    public async Task RunAsync_ReportsQueueResidenceBeforeInjectionCompletes()
    {
        var queue = new PriorityPacketInjectionQueue(maximumForwardingQueueBytes: 32);
        var sendStarted = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var queueLatencyReported = new TaskCompletionSource<TimeSpan>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        using var allowSend = new ManualResetEventSlim(false);
        using var cancellation = new CancellationTokenSource();

        var sendTask = queue.SendPriorityAsync(
            [0x55],
            onQueueLatency: latency => queueLatencyReported.TrySetResult(latency));

        var runTask = Task.Run(async () => await queue.RunAsync(
            _ =>
            {
                sendStarted.TrySetResult();
                allowSend.Wait();
            },
            () => true,
            onRetry: null,
            (_, _) => { },
            cancellation.Token));

        try
        {
            await sendStarted.Task.WaitAsync(TimeSpan.FromSeconds(2));
            var measuredLatency = await queueLatencyReported.Task.WaitAsync(
                TimeSpan.FromSeconds(2));

            Assert.True(measuredLatency >= TimeSpan.Zero);
            Assert.False(sendTask.IsCompleted);
        }
        finally
        {
            allowSend.Set();
            cancellation.Cancel();
        }

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => runTask);
    }

}
