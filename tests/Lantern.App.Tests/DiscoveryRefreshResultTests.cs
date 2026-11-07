using Lantern.App.Services;
using Xunit;

namespace Lantern.App.Tests;

public sealed class DiscoveryRefreshResultTests
{
    [Fact]
    public void StatusMessage_ReportsPacedLocalNetworkDiscovery()
    {
        var result = new DiscoveryRefreshResult(3, 4, 4);

        Assert.Equal(
            "Device inventory refreshed — 3 neighbor-cache entries, 4 known devices; 4 paced ARP discovery requests sent across the selected local IPv4 segment.",
            result.StatusMessage);
    }

    [Fact]
    public void StatusMessage_ReportsWhenDiscoveryIsRateLimited()
    {
        var result = new DiscoveryRefreshResult(3, 4);

        Assert.Equal(
            "Device inventory refreshed — 3 neighbor-cache entries, 4 known devices. No discovery requests were sent; manual discovery is limited to one pass per minute.",
            result.StatusMessage);
    }

    [Fact]
    public void StatusMessage_ReportsWhenDiscoveryCannotStart()
    {
        var result = new DiscoveryRefreshResult(3, 4, 0, "Npcap is not available.");

        Assert.Equal(
            "Device inventory refreshed — 3 neighbor-cache entries, 4 known devices. Local-network discovery was unavailable: Npcap is not available.",
            result.StatusMessage);
    }
}
