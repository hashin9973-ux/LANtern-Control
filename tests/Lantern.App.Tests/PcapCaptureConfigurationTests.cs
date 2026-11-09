using Lantern.App.Services;
using SharpPcap;
using Xunit;

namespace Lantern.App.Tests;

public sealed class PcapCaptureConfigurationTests
{
    [Fact]
    public void ArpDiscovery_UsesPromiscuousCaptureLikeTheWorkingScanner()
    {
        var configuration = PcapCaptureConfiguration.CreateForArpDiscovery();

        Assert.Equal(DeviceModes.Promiscuous, configuration.Mode);
        Assert.True(configuration.Immediate);
    }

    [Fact]
    public void CreateForForwarding_UsesBufferedPacketDelivery()
    {
        var configuration = PcapCaptureConfiguration.CreateForForwarding();

        Assert.Equal(DeviceModes.None, configuration.Mode);
        Assert.False(configuration.Immediate);
        Assert.Equal(100, configuration.ReadTimeout);
        Assert.Equal(8 * 1024 * 1024, configuration.BufferSize);
        Assert.Equal(8 * 1024 * 1024, configuration.KernelBufferSize);
        Assert.Null(configuration.MinToCopy);
    }
}
