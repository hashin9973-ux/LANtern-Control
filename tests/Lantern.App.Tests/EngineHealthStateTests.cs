using Lantern.App.Services;
using Xunit;

namespace Lantern.App.Tests;

public sealed class EngineHealthStateTests
{
    [Fact]
    public void CannotReportHealthyBeforeStartupCompletes()
    {
        var state = new EngineHealthState();

        state.BeginStart();
        Assert.False(state.Refresh(prerequisitesSatisfied: true));
        Assert.False(state.IsHealthy);
    }

    [Fact]
    public void Refresh_RecoversAfterTransientFaultClears()
    {
        var state = new EngineHealthState();
        state.BeginStart();
        state.CompleteStart(prerequisitesSatisfied: true);

        Assert.True(state.IsHealthy);

        state.MarkDegraded();
        Assert.False(state.IsHealthy);

        Assert.True(state.Refresh(prerequisitesSatisfied: true));
        Assert.True(state.IsHealthy);
    }

    [Fact]
    public void Refresh_DoesNotRecoverWhileAnyPrerequisiteRemainsUnhealthy()
    {
        var state = new EngineHealthState();
        state.BeginStart();
        state.CompleteStart(prerequisitesSatisfied: true);
        state.MarkDegraded();

        Assert.False(state.Refresh(prerequisitesSatisfied: false));
        Assert.False(state.IsHealthy);
    }

    [Fact]
    public void Stop_ClearsStartupReadinessAndHealth()
    {
        var state = new EngineHealthState();
        state.BeginStart();
        state.CompleteStart(prerequisitesSatisfied: true);

        state.Stop();

        Assert.False(state.IsHealthy);
        Assert.False(state.Refresh(prerequisitesSatisfied: true));
    }
}
