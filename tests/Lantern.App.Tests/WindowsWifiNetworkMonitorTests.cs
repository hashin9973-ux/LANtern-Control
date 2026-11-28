using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Text;
using Lantern.App.Services;
using Xunit;

namespace Lantern.App.Tests;

public sealed class WindowsWifiNetworkMonitorTests
{
    [Fact]
    public void BssEntryLayout_MatchesNativeWifiStructureSize()
    {
        Assert.Equal(360, WindowsWlanScanSource.BssEntrySize);
    }

    [Fact]
    public void ParseBssList_ExtractsAllVisibleSsidEntries()
    {
        var result = Parse(CreateBssList("HUAWEI-AX3", "Redmi-15-5G", "Cafe-WiFi"));

        Assert.Equal(
            new[] { "Cafe-WiFi", "HUAWEI-AX3", "Redmi-15-5G" },
            result);
    }

    [Fact]
    public void ParseBssList_DeduplicatesSsidAcrossMultipleBssids()
    {
        var result = Parse(CreateBssList("HUAWEI-AX3", "huawei-ax3", "Cafe-WiFi"));

        Assert.Equal(new[] { "Cafe-WiFi", "HUAWEI-AX3" }, result);
    }

    [Fact]
    public void ParseBssList_ReturnsEmptyForSuccessfulEmptyBssList()
    {
        Assert.Empty(Parse(CreateBssList()));
    }

    [Fact]
    public void ParseBssList_RejectsEntryCountOutsideReturnedBuffer()
    {
        var buffer = new byte[sizeof(uint) * 2];
        BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(0, sizeof(uint)), (uint)buffer.Length);
        BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(sizeof(uint), sizeof(uint)), 1);

        Assert.Throws<InvalidDataException>(() => Parse(buffer));
    }

    [Fact]
    public void ParseBssList_RejectsSsidLengthLargerThanDot11Maximum()
    {
        var buffer = CreateBssList("Cafe-WiFi");
        BinaryPrimitives.WriteUInt32LittleEndian(
            buffer.AsSpan(sizeof(uint) * 2, sizeof(uint)),
            33);

        Assert.Throws<InvalidDataException>(() => Parse(buffer));
    }

    [Fact]
    public async Task GetVisibleSsidsAsync_ReusesOnlyARecentSuccessfulScan()
    {
        var source = new FakeWifiScanSource(new[] { "HUAWEI-AX3", "Cafe-WiFi", "cafe-wifi" });
        var monitor = new WindowsWifiNetworkMonitor(source, TimeSpan.FromMinutes(1));

        var first = await monitor.GetVisibleSsidsAsync();
        var second = await monitor.GetVisibleSsidsAsync();

        Assert.Equal(new[] { "Cafe-WiFi", "HUAWEI-AX3" }, first);
        Assert.Equal(first, second);
        Assert.Equal(1, source.ScanCount);
    }

    [Fact]
    public async Task GetVisibleSsidsAsync_DoesNotCacheFailedScan()
    {
        var source = new FakeWifiScanSource(
            new InvalidOperationException("Location permission is missing."),
            new[] { "Cafe-WiFi" });
        var monitor = new WindowsWifiNetworkMonitor(source, TimeSpan.FromMinutes(1));

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => monitor.GetVisibleSsidsAsync());

        var result = await monitor.GetVisibleSsidsAsync();

        Assert.Equal(new[] { "Cafe-WiFi" }, result);
        Assert.Equal(2, source.ScanCount);
    }

    private static IReadOnlyList<string> Parse(byte[] buffer)
    {
        var pointer = Marshal.AllocHGlobal(buffer.Length);
        try
        {
            Marshal.Copy(buffer, 0, pointer, buffer.Length);
            return WindowsWlanScanSource.ParseBssList(pointer);
        }
        finally
        {
            Marshal.FreeHGlobal(pointer);
        }
    }

    private static byte[] CreateBssList(params string[] ssids)
    {
        var entrySize = WindowsWlanScanSource.BssEntrySize;
        var buffer = new byte[sizeof(uint) * 2 + entrySize * ssids.Length];
        BinaryPrimitives.WriteUInt32LittleEndian(
            buffer.AsSpan(0, sizeof(uint)),
            (uint)buffer.Length);
        BinaryPrimitives.WriteUInt32LittleEndian(
            buffer.AsSpan(sizeof(uint), sizeof(uint)),
            (uint)ssids.Length);

        for (var index = 0; index < ssids.Length; index++)
        {
            var bytes = Encoding.UTF8.GetBytes(ssids[index]);
            var entryOffset = sizeof(uint) * 2 + entrySize * index;
            BinaryPrimitives.WriteUInt32LittleEndian(
                buffer.AsSpan(entryOffset, sizeof(uint)),
                (uint)bytes.Length);
            bytes.CopyTo(buffer.AsSpan(entryOffset + sizeof(uint), bytes.Length));
        }

        return buffer;
    }

    private sealed class FakeWifiScanSource(params object[] responses) : IWindowsWifiScanSource
    {
        public int ScanCount { get; private set; }

        public Task<IReadOnlyList<string>> ScanVisibleSsidsAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var responseIndex = Math.Min(ScanCount, responses.Length - 1);
            ScanCount++;

            return responses[responseIndex] switch
            {
                Exception exception => Task.FromException<IReadOnlyList<string>>(exception),
                IReadOnlyList<string> ssids => Task.FromResult(ssids),
                _ => throw new InvalidOperationException("Unexpected fake Wi-Fi scan response.")
            };
        }
    }
}
