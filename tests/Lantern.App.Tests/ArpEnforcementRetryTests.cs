using Lantern.App.Services;
using Xunit;

namespace Lantern.App.Tests;

public sealed class ArpEnforcementRetryTests
{
    [Fact]
    public async Task ExecuteAsync_RetriesTransientFailureAndReturnsAfterSuccess()
    {
        var attempts = 0;
        var retryAttempts = new List<int>();

        await ArpEnforcementRetry.ExecuteAsync(
            () =>
            {
                attempts++;
                if (attempts < 3)
                {
                    throw new IOException("Temporary Npcap send failure.");
                }
            },
            CancellationToken.None,
            (attempt, _) => retryAttempts.Add(attempt));

        Assert.Equal(3, attempts);
        Assert.Equal([2, 3], retryAttempts);
    }

    [Fact]
    public async Task ExecuteAsync_StopsAfterBoundedAttemptsAndPreservesLastFailure()
    {
        var attempts = 0;

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            () => ArpEnforcementRetry.ExecuteAsync(
                () =>
                {
                    attempts++;
                    throw new IOException("Npcap send failed.");
                },
                CancellationToken.None));

        Assert.Equal(ArpEnforcementRetry.MaxAttempts, attempts);
        Assert.Contains("after 3 attempts", exception.Message);
        Assert.IsType<IOException>(exception.InnerException);
        Assert.Equal("Npcap send failed.", exception.InnerException!.Message);
    }

    [Fact]
    public async Task ExecuteAsync_StopsRetryingWhenCancelled()
    {
        using var cancellation = new CancellationTokenSource();
        var attempts = 0;

        var execution = ArpEnforcementRetry.ExecuteAsync(
            () =>
            {
                attempts++;
                throw new IOException("Temporary Npcap send failure.");
            },
            cancellation.Token);
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            async () => await execution);

        Assert.Equal(1, attempts);
    }
}
