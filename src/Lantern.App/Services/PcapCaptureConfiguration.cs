using SharpPcap;

namespace Lantern.App.Services;

public static class PcapCaptureConfiguration
{
    public static DeviceConfiguration CreateForArpDiscovery() =>
        Create(DeviceModes.Promiscuous);

    public static DeviceConfiguration CreateForForwarding() =>
        Create(DeviceModes.None);

    /// <summary>
    /// Opens a dedicated Npcap handle used only for packet injection. It is
    /// intentionally not started for capture, so receive loops never share
    /// their pcap_t handle with the sender.
    /// </summary>
    public static DeviceConfiguration CreateForInjection() =>
        new()
        {
            Mode = DeviceModes.None,
            ReadTimeout = 100,
            Snaplen = 65_536,
            Immediate = false,
        };

    private static DeviceConfiguration Create(DeviceModes mode) =>
        new()
        {
            Mode = mode,
            ReadTimeout = mode == DeviceModes.None ? 100 : 1,
            Snaplen = 65_536,
            BufferSize = 8 * 1024 * 1024,
            KernelBufferSize = 8 * 1024 * 1024,
            MinToCopy = mode == DeviceModes.None ? null : 0,
            // Batch forwarding packets to reduce per-packet wakeups and CPU overhead.
            Immediate = mode != DeviceModes.None,
        };
}
