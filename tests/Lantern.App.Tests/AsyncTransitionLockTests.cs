using Lantern.App.Services;
using Xunit;

namespace Lantern.App.Tests;

public sealed class AsyncTransitionLockTests
{
    [Fact]
    public async Task EnterAsync_SerializesOverlappingLifecycleTransitions()
    {
        var gate = new AsyncTransitionLock();
        using var first = await gate.EnterAsync();
        var secondWaiting = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var secondEntered = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);

        var secondTask = Task.Run(async () =>
        {
            secondWaiting.TrySetResult();
            using var second = await gate.EnterAsync();
            secondEntered.TrySetResult();
        });

        await secondWaiting.Task.WaitAsync(TimeSpan.FromSeconds(2));
        Assert.False(secondEntered.Task.IsCompleted);

        first.Dispose();
        await secondEntered.Task.WaitAsync(TimeSpan.FromSeconds(2));
        await secondTask;
    }

    [Fact]
    public async Task EnterAsync_CancellationDoesNotAcquireOrReleaseTheGate()
    {
        var gate = new AsyncTransitionLock();
        using var first = await gate.EnterAsync();
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            async () =>
            {
                using var second = await gate.EnterAsync(cancellation.Token);
            });

        first.Dispose();
        using var next = await gate.EnterAsync();
    }

    [Fact]
    public async Task EnterAsync_ExceptionalTransitionReleasesTheGate()
    {
        var gate = new AsyncTransitionLock();

        await Assert.ThrowsAsync<InvalidOperationException>(
            async () =>
            {
                using var transition = await gate.EnterAsync();
                throw new InvalidOperationException("simulated startup failure");
            });

        using var next = await gate.EnterAsync();
    }
}
