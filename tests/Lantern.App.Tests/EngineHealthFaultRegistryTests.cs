using Lantern.App.Services;
using Xunit;

namespace Lantern.App.Tests;

public sealed class EngineHealthFaultRegistryTests
{
    [Fact]
    public void ClearingOneFault_DoesNotClearIndependentFaults()
    {
        var faults = new EngineHealthFaultRegistry();

        Assert.True(faults.TrySet("capture-queue", "capture queue full"));
        Assert.True(faults.TrySet("npcap-drops", "Npcap dropped packets"));
        Assert.False(faults.IsHealthy);

        Assert.True(faults.TryClear("capture-queue"));

        Assert.False(faults.IsHealthy);
        Assert.Equal("Npcap dropped packets", faults.PrimaryReason);
    }

    [Fact]
    public void RepeatedFaultForSameKey_DoesNotDuplicateFaultState()
    {
        var faults = new EngineHealthFaultRegistry();

        Assert.True(faults.TrySet("capture-queue", "capture queue full"));
        Assert.False(faults.TrySet("capture-queue", "capture queue still full"));
        Assert.Equal("capture queue full", faults.PrimaryReason);
    }

    [Fact]
    public void Clear_ResetsAllFaults()
    {
        var faults = new EngineHealthFaultRegistry();
        faults.TrySet("npcap", "capture unavailable");
        faults.TrySet("forwarding", "queue full");

        faults.Clear();

        Assert.True(faults.IsHealthy);
        Assert.Null(faults.PrimaryReason);
    }
}
