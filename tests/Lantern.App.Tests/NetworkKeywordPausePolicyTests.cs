using Lantern.App.Services;
using Xunit;

namespace Lantern.App.Tests;

public sealed class NetworkKeywordPausePolicyTests
{
    [Fact]
    public void ShouldPause_RequiresControlToBeEnabled()
    {
        Assert.False(NetworkKeywordPausePolicy.ShouldPause(
            controlEnabled: false,
            connectedSsid: "Home-Network",
            keyword: "Home"));
    }

    [Fact]
    public void ShouldPause_MatchesKeywordCaseInsensitively()
    {
        Assert.True(NetworkKeywordPausePolicy.ShouldPause(
            controlEnabled: true,
            connectedSsid: "Home-Network-5G",
            keyword: "home-network"));
    }

    [Fact]
    public void ShouldPause_ReturnsFalseWhenKeywordIsNotPresent()
    {
        Assert.False(NetworkKeywordPausePolicy.ShouldPause(
            controlEnabled: true,
            connectedSsid: "Guest-WiFi",
            keyword: "Home"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void ShouldPause_ReturnsFalseWhenNoConnectedSsidIsAvailable(string? ssid)
    {
        Assert.False(NetworkKeywordPausePolicy.ShouldPause(
            controlEnabled: true,
            connectedSsid: ssid,
            keyword: "Home"));
    }
}
