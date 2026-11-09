using Lantern.App.Services;
using Xunit;

namespace Lantern.App.Tests;

public sealed class PacketBatchCompletionTests
{
    [Fact]
    public void MarkPacketSent_CompletesOnlyAfterEveryPacketSucceeds()
    {
        var completed = 0;
        var failed = 0;
        var batch = new PacketBatchCompletion(
            3,
            () => Interlocked.Increment(ref completed),
            () => Interlocked.Increment(ref failed));

        batch.MarkPacketSent();
        batch.MarkPacketSent();

        Assert.Equal(0, Volatile.Read(ref completed));
        Assert.Equal(0, Volatile.Read(ref failed));

        batch.MarkPacketSent();

        Assert.Equal(1, Volatile.Read(ref completed));
        Assert.Equal(0, Volatile.Read(ref failed));
    }

    [Fact]
    public void MarkPacketFailed_PreventsLaterSuccessFromConfirmingTheBatch()
    {
        var completed = 0;
        var failed = 0;
        var batch = new PacketBatchCompletion(
            3,
            () => Interlocked.Increment(ref completed),
            () => Interlocked.Increment(ref failed));

        batch.MarkPacketSent();
        batch.MarkPacketFailed();
        batch.MarkPacketSent();
        batch.MarkPacketSent();
        batch.MarkPacketFailed();

        Assert.Equal(0, Volatile.Read(ref completed));
        Assert.Equal(1, Volatile.Read(ref failed));
    }
}