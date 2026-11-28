using System.Collections.Concurrent;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Lantern.App.Services;

internal interface IWindowsWifiScanSource
{
    Task<IReadOnlyList<string>> ScanVisibleSsidsAsync(CancellationToken cancellationToken);
}

/// <summary>
/// Requests a fresh scan on every ready WLAN interface, waits for scan
/// completion, and reads the resulting BSS entries through Native Wi-Fi.
/// </summary>
internal sealed class WindowsWlanScanSource : IWindowsWifiScanSource
{
    private const uint WlanNotificationSourceAcm = 0x00000008;
    private const uint ScanCompleteNotification = 7;
    private const uint ScanFailedNotification = 8;
    private const uint ErrorAccessDenied = 5;
    private const uint ErrorNotSupported = 50;
    private const uint ErrorServiceNotActive = 1062;
    private const uint ErrorNotFound = 1168;
    private const uint ErrorNdisDot11PowerStateInvalid = 0x80342001;
    private const int WlanClientVersion = 2;
    private const int BssListHeaderSize = sizeof(uint) * 2;
    private static readonly TimeSpan ScanTimeout = TimeSpan.FromSeconds(12);

    private readonly ConcurrentDictionary<Guid, TaskCompletionSource<ScanNotification>> pendingScans = new();
    private readonly NativeMethods.WlanNotificationCallback notificationCallback;

    public WindowsWlanScanSource()
    {
        notificationCallback = OnWlanNotification;
    }

    public Task<IReadOnlyList<string>> ScanVisibleSsidsAsync(CancellationToken cancellationToken) =>
        Task.Run(() => ScanVisibleSsids(cancellationToken), cancellationToken);

    private IReadOnlyList<string> ScanVisibleSsids(CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("Visible Wi-Fi scanning requires Windows Native Wi-Fi.");
        }

        cancellationToken.ThrowIfCancellationRequested();

        var openResult = NativeMethods.WlanOpenHandle(
            WlanClientVersion,
            IntPtr.Zero,
            out _,
            out var rawHandle);
        if (openResult != 0)
        {
            if (rawHandle != IntPtr.Zero)
            {
                _ = NativeMethods.WlanCloseHandle(rawHandle, IntPtr.Zero);
            }

            throw CreateNativeApiException("Opening the Windows WLAN client", openResult);
        }

        if (rawHandle == IntPtr.Zero)
        {
            throw new InvalidOperationException("Windows WLAN returned an invalid client handle.");
        }

        using var handle = new SafeWlanHandle(rawHandle);
        RegisterScanNotifications(handle);

        var interfaces = EnumerateInterfaces(handle);
        var readyInterfaces = interfaces
            .Where(item => item.State != 0)
            .ToArray();

        if (readyInterfaces.Length == 0)
        {
            throw new InvalidOperationException(
                "Windows WLAN did not report a ready wireless interface. Enable the Wi-Fi adapter and verify that the WLAN AutoConfig service is running.");
        }

        var visibleSsids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var wlanInterface in readyInterfaces)
        {
            cancellationToken.ThrowIfCancellationRequested();
            RequestAndWaitForScan(handle, wlanInterface, cancellationToken);

            foreach (var ssid in GetInterfaceSsids(handle, wlanInterface.InterfaceGuid))
            {
                visibleSsids.Add(ssid);
            }
        }

        return visibleSsids
            .OrderBy(ssid => ssid, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private void RegisterScanNotifications(SafeWlanHandle handle)
    {
        var result = NativeMethods.WlanRegisterNotification(
            handle,
            WlanNotificationSourceAcm,
            ignoreDuplicate: true,
            notificationCallback,
            IntPtr.Zero,
            IntPtr.Zero,
            out _);

        if (result != 0)
        {
            throw CreateNativeApiException("Registering Windows WLAN scan notifications", result);
        }
    }

    private static IReadOnlyList<WlanInterface> EnumerateInterfaces(SafeWlanHandle handle)
    {
        var result = NativeMethods.WlanEnumInterfaces(handle, IntPtr.Zero, out var list);
        if (result != 0)
        {
            throw CreateNativeApiException("Enumerating wireless interfaces", result);
        }

        if (list == IntPtr.Zero)
        {
            throw new InvalidDataException("Windows WLAN returned an empty interface-list buffer.");
        }

        try
        {
            var count = unchecked((uint)Marshal.ReadInt32(list));
            var entrySize = Marshal.SizeOf<WlanInterfaceInfo>();
            var interfaces = new List<WlanInterface>(checked((int)count));

            for (var index = 0u; index < count; index++)
            {
                var offset = checked(sizeof(uint) * 2 + checked((int)index * entrySize));
                var item = Marshal.PtrToStructure<WlanInterfaceInfo>(IntPtr.Add(list, offset));
                interfaces.Add(new WlanInterface(
                    item.InterfaceGuid,
                    string.IsNullOrWhiteSpace(item.Description)
                        ? item.InterfaceGuid.ToString("D")
                        : item.Description.TrimEnd('\0'),
                    item.State));
            }

            return interfaces;
        }
        finally
        {
            NativeMethods.WlanFreeMemory(list);
        }
    }

    private void RequestAndWaitForScan(
        SafeWlanHandle handle,
        WlanInterface wlanInterface,
        CancellationToken cancellationToken)
    {
        var completion = new TaskCompletionSource<ScanNotification>(
            TaskCreationOptions.RunContinuationsAsynchronously);

        if (!pendingScans.TryAdd(wlanInterface.InterfaceGuid, completion))
        {
            throw new InvalidOperationException(
                $"A Wi-Fi scan is already pending for interface '{wlanInterface.Description}'.");
        }

        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            var interfaceGuid = wlanInterface.InterfaceGuid;
            var result = NativeMethods.WlanScan(
                handle,
                ref interfaceGuid,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero);

            if (result != 0)
            {
                throw CreateNativeApiException(
                    $"Requesting a fresh Wi-Fi scan on '{wlanInterface.Description}'",
                    result);
            }

            ScanNotification notification;
            try
            {
                notification = completion.Task
                    .WaitAsync(ScanTimeout, cancellationToken)
                    .GetAwaiter()
                    .GetResult();
            }
            catch (TimeoutException)
            {
                throw new TimeoutException(
                    $"Windows did not report scan completion for '{wlanInterface.Description}' within {ScanTimeout.TotalSeconds:0} seconds.");
            }

            if (notification.Code == ScanFailedNotification)
            {
                var reason = notification.ReasonCode == 0
                    ? "Windows did not provide a reason code."
                    : $"WLAN reason code 0x{notification.ReasonCode:X8}.";

                throw new InvalidOperationException(
                    $"The Wi-Fi scan failed on '{wlanInterface.Description}'. {reason}");
            }
        }
        finally
        {
            pendingScans.TryRemove(wlanInterface.InterfaceGuid, out _);
        }
    }

    private static IReadOnlyList<string> GetInterfaceSsids(
        SafeWlanHandle handle,
        Guid interfaceGuid)
    {
        var result = NativeMethods.WlanGetNetworkBssList(
            handle,
            ref interfaceGuid,
            IntPtr.Zero,
            3,
            false,
            IntPtr.Zero,
            out var bssList);

        if (result != 0)
        {
            throw CreateNativeApiException(
                $"Reading the fresh BSS list for Wi-Fi interface '{interfaceGuid:D}'",
                result);
        }

        if (bssList == IntPtr.Zero)
        {
            throw new InvalidDataException("Windows WLAN returned an empty BSS-list buffer.");
        }

        try
        {
            return ParseBssList(bssList);
        }
        finally
        {
            NativeMethods.WlanFreeMemory(bssList);
        }
    }

    internal static IReadOnlyList<string> ParseBssList(IntPtr bssList)
    {
        if (bssList == IntPtr.Zero)
        {
            throw new ArgumentNullException(nameof(bssList));
        }

        var totalSize = unchecked((uint)Marshal.ReadInt32(bssList));
        var itemCount = unchecked((uint)Marshal.ReadInt32(bssList, sizeof(uint)));
        var entrySize = Marshal.SizeOf<WlanBssEntry>();

        if (totalSize < BssListHeaderSize)
        {
            throw new InvalidDataException("The WLAN BSS-list header is smaller than its documented structure.");
        }

        var maximumEntries = (totalSize - BssListHeaderSize) / (uint)entrySize;
        if (itemCount > maximumEntries)
        {
            throw new InvalidDataException(
                $"The WLAN BSS list declares {itemCount} entries but its buffer can contain at most {maximumEntries}.");
        }

        var ssids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        for (var index = 0u; index < itemCount; index++)
        {
            var offset = checked(BssListHeaderSize + checked((int)index * entrySize));
            var entry = Marshal.PtrToStructure<WlanBssEntry>(IntPtr.Add(bssList, offset));
            if (entry.Ssid.Length > 32)
            {
                throw new InvalidDataException(
                    $"The WLAN BSS list contains an invalid SSID length of {entry.Ssid.Length} bytes.");
            }

            if (entry.Ssid.Length == 0)
            {
                continue;
            }

            if (entry.Ssid.Bytes is null)
            {
                throw new InvalidDataException("The WLAN BSS entry did not contain its documented SSID byte buffer.");
            }

            var ssid = Encoding.UTF8.GetString(
                entry.Ssid.Bytes,
                0,
                checked((int)entry.Ssid.Length));

            ssids.Add(ssid);
        }

        return ssids
            .OrderBy(ssid => ssid, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    internal static int BssEntrySize => Marshal.SizeOf<WlanBssEntry>();

    private void OnWlanNotification(
        ref WlanNotificationData notification,
        IntPtr context)
    {
        if (notification.NotificationSource != WlanNotificationSourceAcm ||
            notification.NotificationCode is not (ScanCompleteNotification or ScanFailedNotification) ||
            !pendingScans.TryGetValue(notification.InterfaceGuid, out var completion))
        {
            return;
        }

        uint reasonCode = 0;
        try
        {
            if (notification.Data != IntPtr.Zero && notification.DataSize >= sizeof(uint))
            {
                reasonCode = unchecked((uint)Marshal.ReadInt32(notification.Data));
            }
        }
        catch (Exception)
        {
            // A notification callback must not allow managed exceptions to cross the native boundary.
        }

        completion.TrySetResult(new ScanNotification(notification.NotificationCode, reasonCode));
    }

    private static Exception CreateNativeApiException(string operation, uint errorCode)
    {
        var details = errorCode switch
        {
            ErrorAccessDenied =>
                "Windows denied access to nearby Wi-Fi information. On Windows versions with Wi-Fi location privacy controls, enable Location services and 'Let desktop apps access your location' in Windows Settings.",
            ErrorNotSupported =>
                "The WLAN AutoConfig service may be disabled, or the wireless driver does not support this operation.",
            ErrorServiceNotActive =>
                "The WLAN AutoConfig service is not running. Start the WLAN AutoConfig service and retry.",
            ErrorNotFound =>
                "The wireless interface is no longer available. Verify that the Wi-Fi adapter is enabled and retry.",
            ErrorNdisDot11PowerStateInvalid =>
                "The Wi-Fi radio is turned off. Enable the wireless radio and retry.",
            _ => new Win32Exception(unchecked((int)errorCode)).Message,
        };

        return new InvalidOperationException(
            $"{operation} failed with Windows error {errorCode} (0x{errorCode:X8}): {details}");
    }

    private readonly record struct WlanInterface(Guid InterfaceGuid, string Description, int State);

    private readonly record struct ScanNotification(uint Code, uint ReasonCode);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WlanInterfaceInfo
    {
        public Guid InterfaceGuid;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string? Description;

        public int State;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Dot11Ssid
    {
        public uint Length;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32, ArraySubType = UnmanagedType.U1)]
        public byte[]? Bytes;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WlanRateSet
    {
        public uint Length;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 126, ArraySubType = UnmanagedType.U2)]
        public ushort[]? Rates;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WlanBssEntry
    {
        public Dot11Ssid Ssid;
        public uint PhyId;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6, ArraySubType = UnmanagedType.U1)]
        public byte[]? Bssid;

        public int BssType;
        public int PhyType;
        public int Rssi;
        public uint LinkQuality;
        public byte InRegDomain;
        public ushort BeaconPeriod;
        public ulong Timestamp;
        public ulong HostTimestamp;
        public ushort CapabilityInformation;
        public uint CenterFrequency;
        public WlanRateSet RateSet;
        public uint IeOffset;
        public uint IeSize;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WlanNotificationData
    {
        public uint NotificationSource;
        public uint NotificationCode;
        public Guid InterfaceGuid;
        public uint DataSize;
        public IntPtr Data;
    }

    private sealed class SafeWlanHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeWlanHandle(IntPtr handle)
            : base(ownsHandle: true)
        {
            SetHandle(handle);
        }

        protected override bool ReleaseHandle() =>
            NativeMethods.WlanCloseHandle(handle, IntPtr.Zero) == 0;
    }

    private static class NativeMethods
    {
        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        internal delegate void WlanNotificationCallback(
            ref WlanNotificationData notificationData,
            IntPtr context);

        [DllImport("wlanapi.dll", ExactSpelling = true)]
        internal static extern uint WlanOpenHandle(
            uint clientVersion,
            IntPtr reserved,
            out uint negotiatedVersion,
            out IntPtr clientHandle);

        [DllImport("wlanapi.dll", ExactSpelling = true)]
        internal static extern uint WlanCloseHandle(
            IntPtr clientHandle,
            IntPtr reserved);

        [DllImport("wlanapi.dll", ExactSpelling = true)]
        internal static extern uint WlanRegisterNotification(
            SafeWlanHandle clientHandle,
            uint notificationSource,
            [MarshalAs(UnmanagedType.Bool)] bool ignoreDuplicate,
            WlanNotificationCallback callback,
            IntPtr callbackContext,
            IntPtr reserved,
            out uint previousNotificationSource);

        [DllImport("wlanapi.dll", ExactSpelling = true)]
        internal static extern uint WlanEnumInterfaces(
            SafeWlanHandle clientHandle,
            IntPtr reserved,
            out IntPtr interfaceList);

        [DllImport("wlanapi.dll", ExactSpelling = true)]
        internal static extern uint WlanScan(
            SafeWlanHandle clientHandle,
            ref Guid interfaceGuid,
            IntPtr dot11Ssid,
            IntPtr ieData,
            IntPtr reserved);

        [DllImport("wlanapi.dll", ExactSpelling = true)]
        internal static extern uint WlanGetNetworkBssList(
            SafeWlanHandle clientHandle,
            ref Guid interfaceGuid,
            IntPtr dot11Ssid,
            int dot11BssType,
            [MarshalAs(UnmanagedType.Bool)] bool securityEnabled,
            IntPtr reserved,
            out IntPtr bssList);

        [DllImport("wlanapi.dll", ExactSpelling = true)]
        internal static extern void WlanFreeMemory(IntPtr memory);
    }
}
