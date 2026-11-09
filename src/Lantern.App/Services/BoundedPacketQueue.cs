using System.Collections.Concurrent;
using System.Threading.Channels;

namespace Lantern.App.Services;

/// <summary>
/// A single-consumer capture queue with a strict byte budget. Captured data is
/// copied only after reserving capacity because SharpPcap's packet span expires
/// when GetNextPacket is called again.
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
        if (packet.IsEmpty || !TryReserve(packet.Length))
        {
            return false;
        }

        try
        {
            packets.Enqueue(packet.ToArray());
            signal.Writer.TryWrite(true);
            return true;
        }
        catch
        {
            Interlocked.Add(ref bufferedBytes, -packet.Length);
            throw;
        }
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

    private bool TryReserve(int length)
    {
        while (true)
        {
            var current = Interlocked.Read(ref bufferedBytes);
            if (length > maximumBufferedBytes - current)
            {
                return false;
            }

            if (Interlocked.CompareExchange(
                    ref bufferedBytes,
                    current + length,
                    current) == current)
            {
                return true;
            }
        }
    }
}
