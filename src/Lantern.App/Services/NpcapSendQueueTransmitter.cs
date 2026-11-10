using System.IO;
using SharpPcap.LibPcap;

namespace Lantern.App.Services;

/// <summary>
/// Sends frames through libpcap's native send-queue API. On Windows with
/// Npcap, pcap_sendqueue_transmit is implemented using PacketSendPackets,
/// rather than the PacketSendPacket function used by pcap_sendpacket.
/// </summary>
public static class NpcapSendQueueTransmitter
{
    // SharpPcap's Windows pcap_pkthdr is 16 bytes. Reserve additional space
    // for each packet's native queue header and alignment.
    private const int PacketRecordHeaderReserve = 64;

    /// <summary>
    /// Sends one Ethernet frame using pcap_sendqueue_transmit. This method
    /// deliberately refuses SharpPcap's managed fallback, because that
    /// fallback sends through pcap_sendpacket.
    /// </summary>
    public static void Send(LibPcapLiveDevice device, byte[] frame)
    {
        ArgumentNullException.ThrowIfNull(device);
        ArgumentNullException.ThrowIfNull(frame);
        if (frame.Length == 0)
        {
            throw new ArgumentException("An injection frame cannot be empty.", nameof(frame));
        }

        if (!device.Opened)
        {
            throw new InvalidOperationException(
                "Cannot transmit a send queue through a closed Npcap handle.");
        }

        if (!SendQueue.IsHardwareAccelerated)
        {
            throw new NotSupportedException(
                "The loaded capture library does not expose pcap_sendqueue_transmit. " +
                "LANtern will not silently fall back to the pcap_sendpacket path.");
        }

        using var queue = new SendQueue(CalculateBufferSize([frame]));
        if (!queue.Add(frame))
        {
            throw new InvalidOperationException(
                "The native Npcap send queue rejected a frame that should fit in its buffer.");
        }

        var queuedBytes = queue.CurrentLength;
        var transmittedBytes = queue.Transmit(device, SendQueueTransmitModes.Normal);
        if (transmittedBytes != queuedBytes)
        {
            var nativeError = device.LastError;
            var detail = string.IsNullOrWhiteSpace(nativeError)
                ? string.Empty
                : $" Native error: {nativeError}";
            throw new IOException(
                $"Npcap native send queue returned {transmittedBytes} of {queuedBytes} queued bytes.{detail}");
        }
    }

    /// <summary>
    /// Calculates a bounded buffer size for a SharpPcap send queue. Exposed
    /// separately so sizing and validation can be tested without loading Npcap.
    /// </summary>
    public static int CalculateBufferSize(IReadOnlyList<byte[]> frames)
    {
        ArgumentNullException.ThrowIfNull(frames);
        if (frames.Count == 0)
        {
            throw new ArgumentException(
                "A native send queue must contain at least one frame.", nameof(frames));
        }

        long capacity = 0;
        foreach (var frame in frames)
        {
            if (frame is null || frame.Length == 0)
            {
                throw new ArgumentException(
                    "A native send queue cannot contain a null or empty frame.",
                    nameof(frames));
            }

            capacity = checked(capacity + frame.LongLength + PacketRecordHeaderReserve);
        }

        if (capacity > int.MaxValue)
        {
            throw new ArgumentOutOfRangeException(
                nameof(frames),
                "The native send queue exceeds the maximum supported managed buffer size.");
        }

        return (int)capacity;
    }
}
