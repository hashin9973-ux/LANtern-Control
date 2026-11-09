using System.Collections.Concurrent;
using System.Threading.Channels;

namespace Lantern.App.Services;

/// <summary>
/// A single-consumer packet queue with a strict byte budget. Packet data is
/// copied before it is queued because SharpPcap's capture span is only valid
/// until the next GetNextPacket call.
/// </summary>
public sealed class BoundedPacketQueue
{
    private readonly ConcurrentQueue<byte[]> packets = new();
    private readonly Channel<bool> signal = Channel.CreateBounded<bool>(
        new BoundedChannelOptions(1)
        {
            SingleReader = true,
            SingleWriter = false,
            FullMode = BoundedChannelFullMode.DropWrite,
        });
    private readonly long maximumBufferedBytes;
    private long bufferedBytes;

    public BoundedPacketQueue(long maximumBufferedBytes)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maximumBufferedBytes);
        this.maximumBufferedBytes = maximumBufferedBytes;
    }

    public long BufferedBytes => Interlocked.Read(ref bufferedBytes);

    public long MaximumBufferedBytes => maximumBufferedBytes;

    public bool TryWrite(ReadOnlySpan<byte> packet)
    {
        if (packet.IsEmpty)
        {
            return false;
        }

        var ownedPacket = packet.ToArray();
        var currentBytes = Interlocked.Add(ref bufferedBytes, ownedPacket.LongLength);
        if (currentBytes > maximumBufferedBytes)
        {
            Interlocked.Add(ref bufferedBytes, -ownedPacket.LongLength);
            return false;
        }

        packets.Enqueue(ownedPacket);
        signal.Writer.TryWrite(true);
        return true;
    }

    public async ValueTask<byte[]> ReadAsync(CancellationToken cancellationToken = default)
    {
        while (true)
        {
            if (packets.TryDequeue(out var packet))
            {
                Interlocked.Add(ref bufferedBytes, -packet.LongLength);
                return packet;
            }

            await signal.Reader.ReadAsync(cancellationToken);
        }
    }
}
