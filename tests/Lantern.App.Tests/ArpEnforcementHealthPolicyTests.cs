using Lantern.App.Services;
using Xunit;

namespace Lantern.App.Tests;

public sealed class ArpEnforcementHealthPolicyTests
{
    private static readonly TimeSpan MaximumSilence = TimeSpan.FromSeconds(15);

    [Fact]
    public void NoPausedClients_DoesNotRequireArpRefresh()
    {
        Assert.False(ArpEnforcementHealthPolicy.IsStale(
            hasInterceptionTargets: false,
            lastSuccessfulInjectionUtcTicks: 0,
            nowUtcTicks: TimeSpan.TicksPerSecond * 60,
            MaximumSilence));
    }

    [Fact]
    public void PausedClientsWithoutAnySuccessfulSend_AreStale()
    {
        Assert.True(ArpEnforcementHealthPolicy.IsStale(
            hasInterceptionTargets: true,
            lastSuccessfulInjectionUtcTicks: 0,
            nowUtcTicks: TimeSpan.TicksPerSecond * 60,
            MaximumSilence));
    }

    [Fact]
    public void RecentSuccessfulSend_IsHealthy()
    {
        const long now = TimeSpan.TicksPerSecond * 60;
        Assert.False(ArpEnforcementHealthPolicy.IsStale(
            hasInterceptionTargets: true,
            lastSuccessfulInjectionUtcTicks: now - TimeSpan.TicksPerSecond * 10,
            nowUtcTicks: now,
            MaximumSilence));
    }

    [Fact]
    public void MissedEnforcementWindow_IsStale()
    {
        const long now = TimeSpan.TicksPerSecond * 60;
        Assert.True(ArpEnforcementHealthPolicy.IsStale(
            hasInterceptionTargets: true,
            lastSuccessfulInjectionUtcTicks: now - TimeSpan.TicksPerSecond * 16,
            nowUtcTicks: now,
            MaximumSilence));
    }
}
