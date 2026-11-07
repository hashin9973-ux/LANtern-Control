using System.Buffers.Binary;
using System.Text;
using Lantern.App.Services;
using Xunit;

namespace Lantern.App.Tests;

public sealed class LocalMulticastDiscoveryServiceTests
{
    [Fact]
    public void BuildSsdpSearchRequest_UsesSingleRootDeviceDiscoveryQuery()
    {
        var request = Encoding.ASCII.GetString(
            LocalMulticastDiscoveryService.BuildSsdpSearchRequest());

        Assert.StartsWith("M-SEARCH * HTTP/1.1\r\n", request, StringComparison.Ordinal);
        Assert.Contains("HOST: 239.255.255.250:1900\r\n", request, StringComparison.Ordinal);
        Assert.Contains("MAN: \"ssdp:discover\"\r\n", request, StringComparison.Ordinal);
        Assert.Contains("MX: 1\r\n", request, StringComparison.Ordinal);
        Assert.Contains("ST: upnp:rootdevice\r\n", request, StringComparison.Ordinal);
        Assert.EndsWith("\r\n\r\n", request, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("HTTP/1.1 200 OK\r\nST: upnp:rootdevice\r\n\r\n", true)]
    [InlineData("HTTP/1.0 200 OK\r\nST: upnp:rootdevice\r\n\r\n", true)]
    [InlineData("HTTP/1.1 404 Not Found\r\n\r\n", false)]
    [InlineData("not an SSDP response", false)]
    public void IsSsdpResponse_OnlyAcceptsSuccessfulHttpResponses(
        string response,
        bool expected)
    {
        Assert.Equal(
            expected,
            LocalMulticastDiscoveryService.IsSsdpResponse(Encoding.ASCII.GetBytes(response)));
    }

    [Fact]
    public void BuildMdnsServiceBrowseQuery_RequestsDnsSdServiceTypeEnumeration()
    {
        const ushort transactionId = 0x1234;
        var query = LocalMulticastDiscoveryService.BuildMdnsServiceBrowseQuery(transactionId);

        Assert.Equal(
            transactionId,
            BinaryPrimitives.ReadUInt16BigEndian(query.AsSpan(0, 2)));
        Assert.Equal(0, BinaryPrimitives.ReadUInt16BigEndian(query.AsSpan(2, 2)));
        Assert.Equal(1, BinaryPrimitives.ReadUInt16BigEndian(query.AsSpan(4, 2)));

        var labels = new List<string>();
        var offset = 12;
        while (offset < query.Length && query[offset] != 0)
        {
            var length = query[offset++];
            Assert.InRange(length, (byte)1, (byte)63);
            Assert.True(offset + length <= query.Length);
            labels.Add(Encoding.ASCII.GetString(query, offset, length));
            offset += length;
        }

        Assert.Equal(
            ["_services", "_dns-sd", "_udp", "local"],
            labels);
        Assert.Equal(12, BinaryPrimitives.ReadUInt16BigEndian(query.AsSpan(offset + 1, 2)));
        Assert.Equal(1, BinaryPrimitives.ReadUInt16BigEndian(query.AsSpan(offset + 3, 2)));
    }

    [Fact]
    public void IsMdnsServiceBrowseResponse_AcceptsMatchingDnsSdPtrAnswer()
    {
        const ushort transactionId = 0x4321;
        var response = BuildDnsSdResponse(transactionId);

        Assert.True(
            LocalMulticastDiscoveryService.IsMdnsServiceBrowseResponse(
                response,
                transactionId));
    }

    [Fact]
    public void IsMdnsServiceBrowseResponse_RejectsWrongTransactionAndQuestion()
    {
        const ushort transactionId = 0x4321;
        var wrongIdResponse = BuildDnsSdResponse(transactionId);
        var wrongQuestionResponse = BuildDnsSdResponse(transactionId);
        wrongQuestionResponse[13] ^= 0x01;

        Assert.False(
            LocalMulticastDiscoveryService.IsMdnsServiceBrowseResponse(
                wrongIdResponse,
                (ushort)(transactionId + 1)));
        Assert.False(
            LocalMulticastDiscoveryService.IsMdnsServiceBrowseResponse(
                wrongQuestionResponse,
                transactionId));
    }

    private static byte[] BuildDnsSdResponse(ushort transactionId)
    {
        var query = LocalMulticastDiscoveryService.BuildMdnsServiceBrowseQuery(transactionId);
        var recordData = new byte[]
        {
            5, (byte)'_', (byte)'h', (byte)'t', (byte)'t', (byte)'p',
            4, (byte)'_', (byte)'t', (byte)'c', (byte)'p',
            5, (byte)'l', (byte)'o', (byte)'c', (byte)'a', (byte)'l',
            0,
        };

        var response = new byte[query.Length + 12 + recordData.Length];
        Array.Copy(query, response, query.Length);
        response[2] = 0x84; // Standard response with authoritative-answer flag.
        response[3] = 0;
        response[6] = 0;
        response[7] = 1; // One answer.

        var offset = query.Length;
        response[offset++] = 0xc0;
        response[offset++] = 0x0c; // PTR owner name points to the question name.
        BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(offset, 2), 12);
        offset += 2;
        BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(offset, 2), 1);
        offset += 2;
        BinaryPrimitives.WriteUInt32BigEndian(response.AsSpan(offset, 4), 120);
        offset += 4;
        BinaryPrimitives.WriteUInt16BigEndian(
            response.AsSpan(offset, 2),
            (ushort)recordData.Length);
        offset += 2;
        recordData.CopyTo(response, offset);
        return response;
    }
}
