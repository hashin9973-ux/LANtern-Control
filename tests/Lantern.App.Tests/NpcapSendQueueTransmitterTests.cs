using Lantern.App.Services;
using Xunit;

namespace Lantern.App.Tests;

public sealed class NpcapSendQueueTransmitterTests
{
    [Fact]
    public void CalculateBufferSize_ReservesSpaceForThePacketRecordHeader()
    {
        byte[] frame = [0x01, 0x02, 0x03, 0x04];

        var capacity = NpcapSendQueueTransmitter.CalculateBufferSize([frame]);

        Assert.True(capacity >= frame.Length + 64);
    }

    [Fact]
    public void CalculateBufferSize_AccountsForEachFrame()
    {
        byte[] first = [0x01, 0x02, 0x03];
        byte[] second = [0x04, 0x05, 0x06, 0x07];

        var capacity = NpcapSendQueueTransmitter.CalculateBufferSize([first, second]);

        Assert.True(capacity >= first.Length + second.Length + 128);
    }

    [Fact]
    public void CalculateBufferSize_RejectsAnEmptyQueue()
    {
        Assert.Throws<ArgumentException>(
            () => NpcapSendQueueTransmitter.CalculateBufferSize([]));
    }

    [Fact]
    public void CalculateBufferSize_RejectsEmptyFrames()
    {
        Assert.Throws<ArgumentException>(
            () => NpcapSendQueueTransmitter.CalculateBufferSize([[]]));
    }

    [Fact]
    public void CalculateBufferSize_RejectsNullFrames()
    {
        byte[]?[] frames = [null];

        Assert.Throws<ArgumentException>(
            () => NpcapSendQueueTransmitter.CalculateBufferSize(frames!));
    }
}
