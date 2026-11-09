using Lantern.App.Services;
using Xunit;

namespace Lantern.App.Tests;

public sealed class ForwardingShutdownTests
{
    [Fact]
    public async Task RunAsync_RestoresPeersBeforeForwardingStops()
    {
        var forwarding = true;
        var restoredWhileForwarding = false;

        await ForwardingShutdown.RunAsync(
            async () =>
            {
                restoredWhileForwarding = forwarding;
                await Task.Yield();
            },
            () => forwarding = false,
            () => Task.CompletedTask);

        Assert.True(restoredWhileForwarding);
        Assert.False(forwarding);
    }

    [Fact]
    public async Task RunAsync_StillStopsForwardingWhenRestorationFails()
    {
        var forwarding = true;

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => ForwardingShutdown.RunAsync(
                () => throw new InvalidOperationException("restore failed"),
                () => forwarding = false,
                () => Task.CompletedTask));

        Assert.False(forwarding);
    }
    [Fact]
    public async Task RunAsync_StillAwaitsWorkersWhenCancellationFails()
    {
        var workersAwaited = false;

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            () => ForwardingShutdown.RunAsync(
                () => Task.CompletedTask,
                () => throw new InvalidOperationException("cancel failed"),
                () =>
                {
                    workersAwaited = true;
                    return Task.CompletedTask;
                }));

        Assert.Equal("cancel failed", exception.Message);
        Assert.True(workersAwaited);
    }

    [Fact]
    public async Task RunAsync_AggregatesFailuresAfterAwaitingWorkers()
    {
        var workersAwaited = false;

        var exception = await Assert.ThrowsAsync<AggregateException>(
            () => ForwardingShutdown.RunAsync(
                () => throw new IOException("restore failed"),
                () => throw new InvalidOperationException("cancel failed"),
                () =>
                {
                    workersAwaited = true;
                    return Task.CompletedTask;
                }));

        Assert.True(workersAwaited);
        Assert.Collection(
            exception.InnerExceptions,
            failure => Assert.IsType<IOException>(failure),
            failure => Assert.IsType<InvalidOperationException>(failure));
    }

}
