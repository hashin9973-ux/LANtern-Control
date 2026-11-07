using Lantern.App.Services;
using Xunit;

namespace Lantern.App.Tests;

public sealed class DiscoveryRefreshResultTests
{
    [Fact]
    public void StatusMessage_ReportsPacedPresenceChecks()
    {
        var result = new DiscoveryRefreshResult(3, 4, 4);

        Assert.Equal(
            "Device inventory refreshed — 3 cached entries, 4 known devices; 4 paced presence probes sent to previously known IP addresses.",
            result.StatusMessage);
    }

    [Fact]
    public void StatusMessage_ReportsWhenNoPresenceChecksAreDue()
    {
        var result = new DiscoveryRefreshResult(3, 4);

        Assert.Equal(
            "Device inventory refreshed — 3 cached entries, 4 known devices. No presence checks were due; checks are rate-limited.",
            result.StatusMessage);
    }

    [Fact]
    public void StatusMessage_ReportsWhenPresenceChecksCannotStart()
    {
        var result = new DiscoveryRefreshResult(3, 4, 0, "Npcap is not available.");

        Assert.Equal(
            "Device inventory refreshed — 3 cached entries, 4 known devices. Live presence checks were unavailable: Npcap is not available.",
            result.StatusMessage);
    }
}
