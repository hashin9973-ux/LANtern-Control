using Lantern.App.Services;
using Xunit;

namespace Lantern.App.Tests;

public sealed class BackgroundLoopSupervisorTests
{
    [Fact]
    public async Task RunAsync_ReportsFaultedLoopImmediately()
    {
        Exception? reported = null;

        await BackgroundLoopSupervisor.RunAsync(
            "ARP enforcement loop",
            () => Task.FromException(new IOException("Npcap send failed.")),
            CancellationToken.None,
            (_, exception) => reported = exception);

        Assert.IsType<IOException>(reported);
        Assert.Equal("Npcap send failed.", reported!.Message);
    }

    [Fact]
    public async Task RunAsync_ReportsUnexpectedNormalExit()
    {
        Exception? reported = null;

        await BackgroundLoopSupervisor.RunAsync(
            "ARP enforcement loop",
            () => Task.CompletedTask,
            CancellationToken.None,
            (_, exception) => reported = exception);

        Assert.IsType<InvalidOperationException>(reported);
        Assert.Contains("stopped unexpectedly", reported!.Message);
    }

    [Fact]
    public async Task RunAsync_DoesNotReportExpectedCancellation()
    {
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        Exception? reported = null;

        await BackgroundLoopSupervisor.RunAsync(
            "ARP enforcement loop",
            () => Task.FromCanceled(cancellation.Token),
            cancellation.Token,
            (_, exception) => reported = exception);

        Assert.Null(reported);
    }
}
