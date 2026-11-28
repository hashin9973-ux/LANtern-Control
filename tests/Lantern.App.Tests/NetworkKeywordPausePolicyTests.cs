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
            visibleSsids: ["Home-Network"],
            keyword: "Home"));
    }

    [Fact]
    public void FindMatches_FindsKeywordInAnyVisibleNetworkCaseInsensitively()
    {
        string[] visibleSsids =
        [
            "Cafe-WiFi",
            "HUAWEI-AX3",
            "Redmi-15-5G",
        ];

        Assert.Equal(
            new[] { "Redmi-15-5G" },
            NetworkKeywordPausePolicy.FindMatches(
                controlEnabled: true,
                visibleSsids: visibleSsids,
                keyword: "redmi"));
    }

    [Fact]
    public void FindMatches_ReturnsEveryVisibleNetworkContainingKeyword()
    {
        string[] visibleSsids =
        [
            "Huawei-Home",
            "Cafe-WiFi",
            "HUAWEI-Guest",
        ];

        Assert.Equal(
            new[] { "Huawei-Home", "HUAWEI-Guest" },
            NetworkKeywordPausePolicy.FindMatches(
                controlEnabled: true,
                visibleSsids,
                keyword: "huawei"));
    }

    [Fact]
    public void ShouldPause_ReturnsFalseWhenNoVisibleNetworkContainsKeyword()
    {
        Assert.False(NetworkKeywordPausePolicy.ShouldPause(
            controlEnabled: true,
            visibleSsids: ["Guest-WiFi", "Cafe-WiFi"],
            keyword: "Home"));
    }

    [Fact]
    public void ShouldPause_ReturnsFalseWhenNoNetworksAreVisible()
    {
        Assert.False(NetworkKeywordPausePolicy.ShouldPause(
            controlEnabled: true,
            visibleSsids: Array.Empty<string>(),
            keyword: "Home"));
    }

    [Fact]
    public void ShouldPause_ReturnsFalseWhenKeywordIsBlank()
    {
        Assert.False(NetworkKeywordPausePolicy.ShouldPause(
            controlEnabled: true,
            visibleSsids: ["Home-Network"],
            keyword: "   "));
    }

    [Fact]
    public void FindMatches_IgnoresBlankEntriesAndDeduplicatesCaseInsensitively()
    {
        string[] visibleSsids =
        [
            "",
            "HUAWEI-AX3",
            "huawei-ax3",
            "   ",
        ];

        Assert.Equal(
            new[] { "HUAWEI-AX3" },
            NetworkKeywordPausePolicy.FindMatches(
                controlEnabled: true,
                visibleSsids,
                keyword: "huawei"));
    }
}
