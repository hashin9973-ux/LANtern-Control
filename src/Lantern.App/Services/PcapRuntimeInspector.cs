using System.ComponentModel;
using System.IO;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using SharpPcap;

namespace Lantern.App.Services;

public sealed record PcapRuntimeInfo(
    string CaptureLibraryVersion,
    string SharpPcapVersion,
    string? NativeLibraryPath,
    string? NativeLibraryFileVersion,
    string? Error);

public static class PcapRuntimeInspector
{
    private const int MaximumPathLength = 32_768;

    public static PcapRuntimeInfo Inspect()
    {
        string version;
        try
        {
            version = Pcap.Version;
        }
        catch (Exception exception)
        {
            version = $"Unavailable: {exception.Message}";
        }

        IntPtr module = GetModuleHandle("wpcap.dll");
        if (module == IntPtr.Zero)
        {
            var errorCode = Marshal.GetLastWin32Error();
            return new PcapRuntimeInfo(
                version,
                Pcap.SharpPcapVersion.ToString(),
                null,
                null,
                new Win32Exception(errorCode).Message);
        }

        var pathBuffer = new StringBuilder(MaximumPathLength);
        var length = GetModuleFileName(module, pathBuffer, pathBuffer.Capacity);
        if (length == 0 || length >= pathBuffer.Capacity)
        {
            var errorCode = Marshal.GetLastWin32Error();
            return new PcapRuntimeInfo(
                version,
                Pcap.SharpPcapVersion.ToString(),
                null,
                null,
                new Win32Exception(errorCode).Message);
        }

        var path = pathBuffer.ToString();
        string? fileVersion;
        try
        {
            fileVersion = FileVersionInfo.GetVersionInfo(path).FileVersion;
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or ArgumentException)
        {
            fileVersion = null;
        }

        return new PcapRuntimeInfo(
            version,
            Pcap.SharpPcapVersion.ToString(),
            path,
            fileVersion,
            null);
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr GetModuleHandle(string moduleName);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetModuleFileName(
        IntPtr module,
        StringBuilder fileName,
        int size);
}
