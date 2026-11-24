using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace Lantern.App.Services;

/// <summary>
/// Reads the SSID of the currently connected Windows WLAN interface.
/// Native Wi-Fi is preferred because its API is independent of the Windows display language.
/// netsh remains as a fallback for systems where the WLAN API cannot be queried.
/// </summary>
public sealed class WindowsWifiNetworkMonitor
{
    private const uint WlanClientVersion = 2;
    private const int CurrentConnectionOpcode = 7;
    private const int ConnectedInterfaceState = 1;
    private const int MaximumEnumeratedInterfaces = 64;
    private static readonly TimeSpan CommandTimeout = TimeSpan.FromSeconds(4);

    public async Task<string?> GetCurrentSsidAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        // Keep synchronous WLAN service calls off the WPF dispatcher.
        var nativeSsid = await Task.Run(
            TryGetCurrentSsidFromNativeWifi,
            cancellationToken).ConfigureAwait(false);
        if (!string.IsNullOrWhiteSpace(nativeSsid))
        {
            return nativeSsid;
        }

        return await GetCurrentSsidFromNetshAsync(cancellationToken).ConfigureAwait(false);
    }

    private static string? TryGetCurrentSsidFromNativeWifi()
    {
        IntPtr clientHandle = IntPtr.Zero;
        IntPtr interfaceList = IntPtr.Zero;
        try
        {
            var result = WlanOpenHandle(
                WlanClientVersion,
                IntPtr.Zero,
                out _,
                out clientHandle);
            if (result != 0 || clientHandle == IntPtr.Zero)
            {
                return null;
            }

            result = WlanEnumInterfaces(clientHandle, IntPtr.Zero, out interfaceList);
            if (result != 0 || interfaceList == IntPtr.Zero)
            {
                return null;
            }

            // WLAN_INTERFACE_INFO_LIST begins with two DWORD values, followed by
            // its variable-length WLAN_INTERFACE_INFO array.
            var interfaceCount = Marshal.ReadInt32(interfaceList);
            if (interfaceCount is < 0 or > MaximumEnumeratedInterfaces)
            {
                return null;
            }

            var interfaceSize = Marshal.SizeOf<WlanInterfaceInfo>();
            var firstInterfaceOffset = sizeof(uint) * 2;
            for (var index = 0; index < interfaceCount; index++)
            {
                var interfacePointer = IntPtr.Add(
                    interfaceList,
                    firstInterfaceOffset + (index * interfaceSize));
                var wlanInterface = Marshal.PtrToStructure<WlanInterfaceInfo>(interfacePointer);
                if (wlanInterface.State != ConnectedInterfaceState)
                {
                    continue;
                }

                IntPtr connectionData = IntPtr.Zero;
                try
                {
                    result = WlanQueryInterface(
                        clientHandle,
                        ref wlanInterface.InterfaceGuid,
                        CurrentConnectionOpcode,
                        IntPtr.Zero,
                        out _,
                        out connectionData,
                        out _);
                    if (result != 0 || connectionData == IntPtr.Zero)
                    {
                        continue;
                    }

                    var connection = Marshal.PtrToStructure<WlanConnectionAttributes>(connectionData);
                    if (connection.State != ConnectedInterfaceState)
                    {
                        continue;
                    }

                    var ssid = connection.AssociationAttributes.Ssid;
                    if (ssid.Length is 0 or > 32 ||
                        ssid.Bytes is null ||
                        ssid.Bytes.Length < ssid.Length)
                    {
                        continue;
                    }

                    var value = Encoding.UTF8.GetString(
                        ssid.Bytes,
                        0,
                        checked((int)ssid.Length));
                    if (!string.IsNullOrWhiteSpace(value))
                    {
                        return value;
                    }
                }
                finally
                {
                    if (connectionData != IntPtr.Zero)
                    {
                        WlanFreeMemory(connectionData);
                    }
                }
            }

            return null;
        }
        catch (Exception exception) when (
            exception is DllNotFoundException or
                EntryPointNotFoundException or
                BadImageFormatException or
                MarshalDirectiveException or
                ArgumentException or
                OverflowException or
                InvalidOperationException)
        {
            // Fall back to netsh on systems where Native Wi-Fi is unavailable.
            return null;
        }
        finally
        {
            if (interfaceList != IntPtr.Zero)
            {
                WlanFreeMemory(interfaceList);
            }

            if (clientHandle != IntPtr.Zero)
            {
                _ = WlanCloseHandle(clientHandle, IntPtr.Zero);
            }
        }
    }

    private async Task<string?> GetCurrentSsidFromNetshAsync(CancellationToken cancellationToken)
    {
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = "netsh.exe",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            },
        };
        process.StartInfo.ArgumentList.Add("wlan");
        process.StartInfo.ArgumentList.Add("show");
        process.StartInfo.ArgumentList.Add("interfaces");

        var started = false;
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!process.Start()) return null;
            started = true;
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(CommandTimeout);
            var outputTask = process.StandardOutput.ReadToEndAsync(timeout.Token);
            var errorTask = process.StandardError.ReadToEndAsync(timeout.Token);
            try
            {
                await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
                var output = await outputTask.ConfigureAwait(false);
                _ = await errorTask.ConfigureAwait(false);
                return process.ExitCode == 0 ? ParseConnectedSsid(output) : null;
            }
            catch (OperationCanceledException)
            {
                TryKill(process);
                try
                {
                    await Task.WhenAll(outputTask, errorTask).ConfigureAwait(false);
                }
                catch (Exception exception) when (
                    exception is OperationCanceledException or IOException)
                {
                    // The process was cancelled or terminated during cleanup.
                }

                if (cancellationToken.IsCancellationRequested)
                    throw;

                return null;
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is Win32Exception or InvalidOperationException or IOException)
        {
            return null;
        }
        finally
        {
            if (started) TryKill(process);
        }
    }

    public static string? ParseConnectedSsid(string output)
    {
        ArgumentNullException.ThrowIfNull(output);

        string? candidateSsid = null;
        var stateSaysConnected = false;
        var hasAssociatedBssid = false;

        string? CompleteInterface()
        {
            return !string.IsNullOrWhiteSpace(candidateSsid) &&
                   (stateSaysConnected || hasAssociatedBssid)
                ? candidateSsid
                : null;
        }

        void ResetInterface()
        {
            candidateSsid = null;
            stateSaysConnected = false;
            hasAssociatedBssid = false;
        }

        foreach (var line in output.Split(['\r', '\n']))
        {
            if (string.IsNullOrWhiteSpace(line))
            {
                var completed = CompleteInterface();
                if (completed is not null)
                {
                    return completed;
                }

                ResetInterface();
                continue;
            }

            var separator = line.IndexOf(':');
            if (separator <= 0) continue;
            var key = line[..separator].Trim();
            var value = line[(separator + 1)..].Trim();

            if (key.Equals("Name", StringComparison.OrdinalIgnoreCase))
            {
                var completed = CompleteInterface();
                if (completed is not null)
                {
                    return completed;
                }

                ResetInterface();
            }
            else if (key.Equals("State", StringComparison.OrdinalIgnoreCase))
            {
                stateSaysConnected =
                    value.Equals("connected", StringComparison.OrdinalIgnoreCase);
            }
            else if (key.Equals("SSID", StringComparison.OrdinalIgnoreCase))
            {
                candidateSsid = value;
            }
            else if (key.Equals("BSSID", StringComparison.OrdinalIgnoreCase))
            {
                hasAssociatedBssid = IsUsableBssid(value);
            }
        }

        return CompleteInterface();
    }

    private static bool IsUsableBssid(string value)
    {
        var hexadecimal = new string(value.Where(Uri.IsHexDigit).ToArray());
        return hexadecimal.Length == 12 &&
               hexadecimal.Any(character => character != '0');
    }

    private static void TryKill(Process process)
    {
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
                process.WaitForExit();
            }
        }
        catch (Exception exception) when (
            exception is InvalidOperationException or Win32Exception)
        {
        }
    }

    private enum WlanInterfaceState
    {
        NotReady,
        Connected,
        AdHocNetworkFormed,
        Disconnecting,
        Disconnected,
        Associating,
        Discovering,
        Authenticating,
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WlanInterfaceInfo
    {
        public Guid InterfaceGuid;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string InterfaceDescription;

        public WlanInterfaceState State;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Dot11Ssid
    {
        public uint Length;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
        public byte[] Bytes;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WlanAssociationAttributes
    {
        public Dot11Ssid Ssid;
        public int BssType;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
        public byte[] Bssid;

        public int PhyType;
        public uint PhyIndex;
        public uint SignalQuality;
        public uint ReceiveRate;
        public uint TransmitRate;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WlanSecurityAttributes
    {
        public int SecurityEnabled;
        public int OneXEnabled;
        public int AuthenticationAlgorithm;
        public int CipherAlgorithm;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WlanConnectionAttributes
    {
        public WlanInterfaceState State;
        public int ConnectionMode;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string ProfileName;

        public WlanAssociationAttributes AssociationAttributes;
        public WlanSecurityAttributes SecurityAttributes;
    }

    [DllImport("wlanapi.dll", ExactSpelling = true)]
    private static extern uint WlanOpenHandle(
        uint clientVersion,
        IntPtr reserved,
        out uint negotiatedVersion,
        out IntPtr clientHandle);

    [DllImport("wlanapi.dll", ExactSpelling = true)]
    private static extern uint WlanEnumInterfaces(
        IntPtr clientHandle,
        IntPtr reserved,
        out IntPtr interfaceList);

    [DllImport("wlanapi.dll", ExactSpelling = true)]
    private static extern uint WlanQueryInterface(
        IntPtr clientHandle,
        ref Guid interfaceGuid,
        int opcode,
        IntPtr reserved,
        out uint dataSize,
        out IntPtr data,
        out int valueType);

    [DllImport("wlanapi.dll", ExactSpelling = true)]
    private static extern void WlanFreeMemory(IntPtr memory);

    [DllImport("wlanapi.dll", ExactSpelling = true)]
    private static extern uint WlanCloseHandle(IntPtr clientHandle, IntPtr reserved);
}
