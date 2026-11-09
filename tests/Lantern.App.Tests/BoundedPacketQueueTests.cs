using Lantern.App.Services;
using Xunit;

namespace Lantern.App.Tests;

public sealed class BoundedPacketQueueTests
{
    [Fact]
    public async Task TryWrite_EnforcesByteBudgetAndReleasesBytesAfterRead()
    {
        var queue = new BoundedPacketQueue(maximumBufferedBytes: 8);

        Assert.True(queue.TryWrite([1, 2, 3, 4]));
        Assert.True(queue.TryWrite([5, 6, 7, 8]));
        Assert.False(queue.TryWrite([9]));
        Assert.Equal(8, queue.BufferedBytes);

        Assert.Equal(new byte[] { 1, 2, 3, 4 }, await queue.ReadAsync());
        Assert.Equal(4, queue.BufferedBytes);

        Assert.True(queue.TryWrite([9, 10, 11, 12]));
        Assert.Equal(8, queue.BufferedBytes);
    }

    [Fact]
    public async Task ReadAsync_ObservesCancellationWhenQueueIsEmpty()
    {
        var queue = new BoundedPacketQueue(maximumBufferedBytes: 8);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => queue.ReadAsync(cancellation.Token).AsTask());
    }

    [Fact]
    public void Constructor_RejectsInvalidByteBudget()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new BoundedPacketQueue(0));
        Assert.Throws<ArgumentOutOfRangeException>(() => new BoundedPacketQueue(-1));
    }
}
