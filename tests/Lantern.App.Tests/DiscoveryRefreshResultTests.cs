using Lantern.App.Services;
using Xunit;

namespace Lantern.App.Tests;

public sealed class DiscoveryRefreshResultTests
{
    [Fact]
    public void StatusMessage_ReportsValidatedResponsesAndRetries()
    {
        var result = new DiscoveryRefreshResult(
            3,
            7,
            258,
            DevicesResponded: 6,
            RetryRequestsSent: 6,
            CandidateHosts: 252);

        Assert.Equal(
            "Device inventory refreshed — 3 neighbor-cache entries, 7 known devices. " +
            "ARP replies received from 6 of 252 candidate addresses after 258 paced requests (6 retries).",
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

    [Fact]
    public void EmptyProbeResult_ContainsNoRequestsOrResponses()
    {
        Assert.Equal(
            new DiscoveryProbeResult(0, 0, 0, 0),
            DiscoveryProbeResult.Empty);
    }
}
