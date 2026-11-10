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
            498,
            DevicesResponded: 6,
            RetryRequestsSent: 246,
            CandidateHosts: 252);

        Assert.Equal(
            "Device inventory refreshed — 3 neighbor-cache entries, 7 known devices. " +
            "ARP replies received from 6 of 252 candidate addresses after 498 paced requests " +
            "(maximum 100 ARP requests per second) (246 retries).",
            result.StatusMessage);
    }

    [Fact]
    public void StatusMessage_ReportsWhenNoArpDiscoveryRequestsWereNeeded()
    {
        var result = new DiscoveryRefreshResult(3, 4);

        Assert.Equal(
            "Device inventory refreshed — 3 neighbor-cache entries, 4 known devices. No ARP discovery requests were needed during this pass.",
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
