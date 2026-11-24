using Lantern.App.Services;
using Xunit;

namespace Lantern.App.Tests;

public sealed class WindowsWifiNetworkMonitorTests
{
    [Fact]
    public void ParseConnectedSsid_ReturnsSsidForConnectedInterface()
    {
        const string output = """
            There is 1 interface on the system:

                Name                   : Wi-Fi
                Description            : Wireless adapter
                GUID                   : 00000000-0000-0000-0000-000000000000
                Physical address       : 00:11:22:33:44:55
                State                  : connected
                SSID                   : Home-Network-5G
                BSSID                  : 00:11:22:33:44:66
            """;
        Assert.Equal("Home-Network-5G", WindowsWifiNetworkMonitor.ParseConnectedSsid(output));
    }

    [Fact]
    public void ParseConnectedSsid_IgnoresDisconnectedInterfaceAndBssid()
    {
        const string output = """
            Name : Wi-Fi
            State : disconnected
            SSID : Saved-Network
            BSSID : 00:11:22:33:44:66
            """;
        Assert.Null(WindowsWifiNetworkMonitor.ParseConnectedSsid(output));
    }

    [Fact]
    public void ParseConnectedSsid_SelectsConnectedInterfaceAfterDisconnectedOne()
    {
        const string output = """
            Name : Wi-Fi
            State : disconnected
            SSID : Saved-Network

            Name : Wi-Fi 2
            State : connected
            SSID : Current-Network
            """;
        Assert.Equal("Current-Network", WindowsWifiNetworkMonitor.ParseConnectedSsid(output));
    }
}
