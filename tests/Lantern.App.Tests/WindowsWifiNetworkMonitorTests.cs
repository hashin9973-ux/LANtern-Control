using Lantern.App.Services;
using Xunit;

namespace Lantern.App.Tests;

public sealed class WindowsWifiNetworkMonitorTests
{
    [Fact]
    public void ParseVisibleSsids_ExtractsAllNumberedSsidEntries()
    {
        const string output = """
            There are 3 networks currently visible.

            SSID 1 : HUAWEI-AX3
                Network type            : Infrastructure
                Authentication          : WPA2-Personal
                Encryption              : CCMP
                BSSID 1                 : 00:11:22:33:44:55

            SSID 2 : Redmi-15-5G
                Network type            : Infrastructure
                Authentication          : WPA2-Personal
                Encryption              : CCMP
                BSSID 1                 : 00:11:22:33:44:66

            SSID 3 : Cafe-WiFi
                Network type            : Infrastructure
                Authentication          : Open
                Encryption              : None
                BSSID 1                 : 00:11:22:33:44:77
            """;

        Assert.Equal(
            new[] { "Cafe-WiFi", "HUAWEI-AX3", "Redmi-15-5G" },
            WindowsWifiNetworkMonitor.ParseVisibleSsids(output));
    }

    [Fact]
    public void ParseVisibleSsids_RemovesBlankAndCaseInsensitiveDuplicateNames()
    {
        const string output = """
            There are 3 networks currently visible.
            SSID 1 : HUAWEI-AX3
            SSID 2 :
            SSID 3 : huawei-ax3
            """;

        Assert.Equal(
            new[] { "HUAWEI-AX3" },
            WindowsWifiNetworkMonitor.ParseVisibleSsids(output));
    }

    [Theory]
    [InlineData("There are 0 networks currently visible.")]
    [InlineData("There is no network currently visible.")]
    public void ParseVisibleSsids_ReturnsEmptyWhenNetshExplicitlyReportsNoVisibleNetworks(
        string output)
    {
        Assert.Empty(WindowsWifiNetworkMonitor.ParseVisibleSsids(output));
    }

    [Fact]
    public void ParseVisibleSsids_RejectsUnrecognizedOutputInsteadOfReportingNoMatches()
    {
        const string output = """
            Wireless AutoConfig service is not running.
            """;

        Assert.Throws<InvalidDataException>(
            () => WindowsWifiNetworkMonitor.ParseVisibleSsids(output));
    }

    [Fact]
    public void ParseVisibleSsids_TrimsWhitespaceAroundNetworkNames()
    {
        const string output = """
            There are 1 networks currently visible.
            SSID 1 :   My Wi-Fi Network
            """;

        Assert.Equal(
            new[] { "My Wi-Fi Network" },
            WindowsWifiNetworkMonitor.ParseVisibleSsids(output));
    }
}
