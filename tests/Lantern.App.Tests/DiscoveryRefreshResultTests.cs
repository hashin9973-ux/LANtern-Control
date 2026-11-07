using Lantern.App.Services;
using Xunit;

namespace Lantern.App.Tests;

public sealed class DiscoveryRefreshResultTests
{
    [Fact]
    public void StatusMessage_ReportsPassiveInventoryAndConfirmsNoProbesWereSent()
    {
        var result = new DiscoveryRefreshResult(3, 4);

        Assert.Equal(
            "Device inventory refreshed — 3 cached entries, 4 known devices. No scan probes were sent.",
            result.StatusMessage);
    }
}
