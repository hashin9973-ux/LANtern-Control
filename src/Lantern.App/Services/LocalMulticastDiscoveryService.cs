using System.Net;
using System.Net.Sockets;
using System.Text;
using Lantern.Core.Networking;

namespace Lantern.App.Services;

/// <summary>
/// Performs a small number of link-local service-discovery queries. The
/// queries are multicast rather than a sweep of additional ports on every host.
/// Only responses from the current scan's unconfirmed local IPv4 candidates
/// are returned.
/// </summary>
public sealed class LocalMulticastDiscoveryService
{
    private const int MaximumResponsesPerProtocol = 253;
    private const int MaximumDatagramBytes = 16 * 1024;

    private static readonly IPEndPoint SsdpEndpoint =
        new(IPAddress.Parse("239.255.255.250"), 1900);

    private static readonly IPEndPoint MdnsEndpoint =
        new(IPAddress.Parse("224.0.0.251"), 5353);

    private static readonly TimeSpan ResponseWindow = TimeSpan.FromMilliseconds(1400);

    public async Task<IReadOnlyList<DiscoveredHost>> ScanAsync(
        AdapterProfile adapter,
        IReadOnlySet<IPAddress> allowedAddresses,
        Func<Func<Task>, CancellationToken, Task> pacedSend,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(adapter);
        ArgumentNullException.ThrowIfNull(allowedAddresses);
        ArgumentNullException.ThrowIfNull(pacedSend);

        if (allowedAddresses.Count == 0)
        {
            return [];
        }

        // This socket uses an ephemeral source port, so mDNS responders send
        // a legacy unicast response to it and repeat the query identifier.
        // Multicast mDNS query identifiers are specified as zero.
        const ushort transactionId = 0;
        var ssdpTask = ScanSsdpAsync(
            adapter,
            allowedAddresses,
            pacedSend,
            cancellationToken);
        var mdnsTask = ScanMdnsServiceTypesAsync(
            adapter,
            allowedAddresses,
            transactionId,
            pacedSend,
            cancellationToken);

        var results = await Task.WhenAll(ssdpTask, mdnsTask).ConfigureAwait(false);
        return results
            .SelectMany(result => result)
            .GroupBy(host => host.Address)
            .Select(group => group.First())
            .OrderBy(host => ToUInt32(host.Address))
            .ToArray();
    }

    public static byte[] BuildSsdpSearchRequest()
    {
        const string request =
            "M-SEARCH * HTTP/1.1\r\n" +
            "HOST: 239.255.255.250:1900\r\n" +
            "MAN: \"ssdp:discover\"\r\n" +
            "MX: 1\r\n" +
            "ST: upnp:rootdevice\r\n" +
            "USER-AGENT: LANtern-Control/0.1 UPnP/1.1\r\n" +
            "\r\n";
        return Encoding.ASCII.GetBytes(request);
    }

    public static byte[] BuildMdnsServiceBrowseQuery(ushort transactionId)
    {
        using var stream = new MemoryStream();
        WriteUInt16(stream, transactionId);
        WriteUInt16(stream, 0);
        WriteUInt16(stream, 1);
        WriteUInt16(stream, 0);
        WriteUInt16(stream, 0);
        WriteUInt16(stream, 0);

        foreach (var label in new[] { "_services", "_dns-sd", "_udp", "local" })
        {
            var bytes = Encoding.ASCII.GetBytes(label);
            stream.WriteByte((byte)bytes.Length);
            stream.Write(bytes);
        }

        stream.WriteByte(0);
        WriteUInt16(stream, 12); // PTR
        WriteUInt16(stream, 1);  // IN
        return stream.ToArray();
    }

    public static bool IsSsdpResponse(ReadOnlySpan<byte> packet)
    {
        if (packet.Length is < 12 or > MaximumDatagramBytes)
        {
            return false;
        }

        var lineEnd = packet.IndexOf("\r\n"u8);
        if (lineEnd <= 0)
        {
            return false;
        }

        var statusLine = packet[..lineEnd];
        if (!statusLine.StartsWith("HTTP/1.1 200 "u8) &&
            !statusLine.StartsWith("HTTP/1.0 200 "u8))
        {
            return false;
        }

        var headers = Encoding.ASCII.GetString(packet[(lineEnd + 2)..]);
        foreach (var header in headers.Split("\\r\\n", StringSplitOptions.RemoveEmptyEntries))
        {
            var separator = header.IndexOf(':');
            if (separator < 0)
            {
                continue;
            }

            var name = header[..separator].Trim();
            var value = header[(separator + 1)..].Trim();
            if (string.Equals(name, "ST", StringComparison.OrdinalIgnoreCase) &&
                string.Equals(value, "upnp:rootdevice", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    public static bool IsMdnsServiceBrowseResponse(
        ReadOnlySpan<byte> packet,
        ushort transactionId)
    {
        if (packet.Length is < 12 or > MaximumDatagramBytes ||
            ReadUInt16(packet, 0) != transactionId)
        {
            return false;
        }

        var flags = ReadUInt16(packet, 2);
        var answerCount = ReadUInt16(packet, 6);
        if ((flags & 0x8000) == 0 || // QR must indicate a response.
            (flags & 0x7800) != 0 || // Only the standard query opcode is accepted.
            (flags & 0x000f) != 0 || // Reject DNS errors.
            ReadUInt16(packet, 4) != 1 ||
            answerCount == 0)
        {
            return false;
        }

        var offset = 12;
        if (!TryReadDnsName(packet, ref offset, out var questionName) ||
            !string.Equals(
                questionName,
                "_services._dns-sd._udp.local",
                StringComparison.OrdinalIgnoreCase) ||
            offset + 4 > packet.Length)
        {
            return false;
        }

        var questionType = ReadUInt16(packet, offset);
        var questionClass = (ushort)(ReadUInt16(packet, offset + 2) & 0x7fff);
        if (questionType != 12 || questionClass != 1)
        {
            return false;
        }

        offset += 4;
        for (var index = 0; index < answerCount; index++)
        {
            if (!TryReadDnsName(packet, ref offset, out var answerName) ||
                offset + 10 > packet.Length)
            {
                return false;
            }

            var answerType = ReadUInt16(packet, offset);
            var answerClass = (ushort)(ReadUInt16(packet, offset + 2) & 0x7fff);
            var dataLength = ReadUInt16(packet, offset + 8);
            offset += 10;
            if (offset + dataLength > packet.Length)
            {
                return false;
            }

            if (answerType == 12 &&
                answerClass == 1 &&
                string.Equals(answerName, questionName, StringComparison.OrdinalIgnoreCase) &&
                dataLength > 0)
            {
                return true;
            }

            offset += dataLength;
        }

        return false;
    }

    private static Task<IReadOnlyList<DiscoveredHost>> ScanSsdpAsync(
        AdapterProfile adapter,
        IReadOnlySet<IPAddress> allowedAddresses,
        Func<Func<Task>, CancellationToken, Task> pacedSend,
        CancellationToken cancellationToken) =>
        ScanProtocolAsync(
            adapter,
            allowedAddresses,
            SsdpEndpoint,
            BuildSsdpSearchRequest(),
            multicastTtl: 1,
            HostDiscoveryMethod.Ssdp,
            packet => IsSsdpResponse(packet.Span),
            static sender => true,
            pacedSend,
            cancellationToken);

    private static Task<IReadOnlyList<DiscoveredHost>> ScanMdnsServiceTypesAsync(
        AdapterProfile adapter,
        IReadOnlySet<IPAddress> allowedAddresses,
        ushort transactionId,
        Func<Func<Task>, CancellationToken, Task> pacedSend,
        CancellationToken cancellationToken) =>
        ScanProtocolAsync(
            adapter,
            allowedAddresses,
            MdnsEndpoint,
            BuildMdnsServiceBrowseQuery(transactionId),
            multicastTtl: 255,
            HostDiscoveryMethod.MdnsServiceBrowse,
            packet => IsMdnsServiceBrowseResponse(packet.Span, transactionId),
            static sender => sender.Port == 5353,
            pacedSend,
            cancellationToken);

    private static async Task<IReadOnlyList<DiscoveredHost>> ScanProtocolAsync(
        AdapterProfile adapter,
        IReadOnlySet<IPAddress> allowedAddresses,
        IPEndPoint destination,
        byte[] query,
        short multicastTtl,
        HostDiscoveryMethod method,
        Func<ReadOnlyMemory<byte>, bool> isValidResponse,
        Func<IPEndPoint, bool> isValidSender,
        Func<Func<Task>, CancellationToken, Task> pacedSend,
        CancellationToken cancellationToken)
    {
        try
        {
            using var client = new UdpClient(AddressFamily.InterNetwork);
            client.Client.Bind(new IPEndPoint(adapter.LocalAddress, 0));
            client.Ttl = multicastTtl;

            Func<Task> send = async () =>
            {
                _ = await client.SendAsync(
                    query.AsMemory(),
                    destination,
                    cancellationToken).ConfigureAwait(false);
            };
            await pacedSend(send, cancellationToken).ConfigureAwait(false);

            using var receiveTimeout = CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken);
            receiveTimeout.CancelAfter(ResponseWindow);

            var responders = new HashSet<IPAddress>();
            while (responders.Count < MaximumResponsesPerProtocol)
            {
                UdpReceiveResult response;
                try
                {
                    response = await client.ReceiveAsync(receiveTimeout.Token)
                        .ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
                {
                    break;
                }

                var sender = response.RemoteEndPoint;
                if (response.Buffer.Length > MaximumDatagramBytes ||
                    sender.Address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork ||
                    !isValidSender(sender) ||
                    !allowedAddresses.Contains(sender.Address) ||
                    !isValidResponse(response.Buffer))
                {
                    continue;
                }

                responders.Add(sender.Address);
            }

            return responders
                .Select(address => new DiscoveredHost(address, method))
                .ToArray();
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (SocketException)
        {
            // Multicast may be unavailable on a selected adapter. The ordinary
            // per-address checks still run, so this optional path must not fail them.
            return [];
        }
    }

    private static bool TryReadDnsName(
        ReadOnlySpan<byte> packet,
        ref int offset,
        out string name)
    {
        var labels = new List<string>();
        var cursor = offset;
        var resumeOffset = -1;
        var jumps = 0;
        while (cursor < packet.Length && jumps <= packet.Length)
        {
            var length = packet[cursor++];
            if (length == 0)
            {
                offset = resumeOffset >= 0 ? resumeOffset : cursor;
                name = string.Join('.', labels);
                return true;
            }

            if ((length & 0xc0) == 0xc0)
            {
                if (cursor >= packet.Length)
                {
                    break;
                }

                var pointer = ((length & 0x3f) << 8) | packet[cursor++];
                if (pointer >= packet.Length)
                {
                    break;
                }

                resumeOffset = resumeOffset >= 0 ? resumeOffset : cursor;
                cursor = pointer;
                jumps++;
                continue;
            }

            if ((length & 0xc0) != 0 || cursor + length > packet.Length)
            {
                break;
            }

            labels.Add(Encoding.UTF8.GetString(packet.Slice(cursor, length)));
            cursor += length;
        }

        name = string.Empty;
        return false;
    }

    private static ushort ReadUInt16(ReadOnlySpan<byte> bytes, int offset) =>
        (ushort)((bytes[offset] << 8) | bytes[offset + 1]);

    private static void WriteUInt16(Stream stream, ushort value)
    {
        stream.WriteByte((byte)(value >> 8));
        stream.WriteByte((byte)value);
    }

    private static uint ToUInt32(IPAddress address)
    {
        var bytes = address.GetAddressBytes();
        return ((uint)bytes[0] << 24) |
               ((uint)bytes[1] << 16) |
               ((uint)bytes[2] << 8) |
               bytes[3];
    }
}
