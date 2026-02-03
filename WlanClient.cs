using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

internal sealed partial class WlanClient : IDisposable
{
    private readonly IntPtr _clientHandle;
    private readonly WlanNotificationCallback _notificationCallback;
    private TaskCompletionSource<bool>? _connectTcs;
    private TaskCompletionSource<bool>? _scanTcs;
    private bool _disposed;

    public WlanClient()
    {
        ThrowOnError(WlanOpenHandle(2, IntPtr.Zero, out var negotiatedVersion, out _clientHandle), "WlanOpenHandle");
        _notificationCallback = OnNotification;
        ThrowOnError(WlanRegisterNotification(_clientHandle, WLAN_NOTIFICATION_SOURCE.ACM, false, _notificationCallback, IntPtr.Zero, IntPtr.Zero, out _), "WlanRegisterNotification");
        AppDomain.CurrentDomain.ProcessExit += (_, __) => Dispose();
        AppDomain.CurrentDomain.UnhandledException += (_, __) => Dispose();
    }

    public Guid? GetPrimaryInterface()
    {
        var interfaces = GetInterfaces();
        // 控制台输出网卡信息
        foreach (var iface in interfaces)
        {
            Console.WriteLine($"[{DateTime.Now:yyyyMMdd HH:mm:ss}] Found interface: {iface.strInterfaceDescription} (State: {iface.isState}, GUID: {iface.InterfaceGuid})");
        }
        return interfaces.Count > 0 ? interfaces[0].InterfaceGuid : null;
    }

    public IReadOnlyList<WLAN_INTERFACE_INFO> GetInterfaces()
    {
        EnsureNotDisposed();
        ThrowOnError(WlanEnumInterfaces(_clientHandle, IntPtr.Zero, out var listPtr), "WlanEnumInterfaces");
        try
        {
            var result = new List<WLAN_INTERFACE_INFO>();
            var header = Marshal.PtrToStructure<WLAN_INTERFACE_INFO_LIST_HEADER>(listPtr);
            var itemPtr = IntPtr.Add(listPtr, Marshal.SizeOf<WLAN_INTERFACE_INFO_LIST_HEADER>());
            for (var i = 0; i < header.dwNumberOfItems; i++)
            {
                var info = Marshal.PtrToStructure<WLAN_INTERFACE_INFO>(itemPtr);
                result.Add(info);

                itemPtr = IntPtr.Add(itemPtr, Marshal.SizeOf<WLAN_INTERFACE_INFO>());
            }

            return result;
        }
        finally
        {
            WlanFreeMemory(listPtr);
        }
    }

    public async Task ConnectAsync(Guid interfaceId, string ssid, string? bssid, CancellationToken cancellationToken)
    {
        EnsureNotDisposed();

        if (string.IsNullOrWhiteSpace(ssid))
        {
            throw new ArgumentException("SSID cannot be empty.", nameof(ssid));
        }

        var ssidStruct = WlanNative.CreateSsid(ssid);
        var ssidPtr = Marshal.AllocHGlobal(Marshal.SizeOf<DOT11_SSID>());
        Marshal.StructureToPtr(ssidStruct, ssidPtr, false);

        IntPtr bssidPtr = IntPtr.Zero;
        IntPtr profilePtr = IntPtr.Zero;
        try
        {
            if (!string.IsNullOrWhiteSpace(bssid))
            {
                bssidPtr = WlanNative.CreateBssidList(bssid!);
            }

            profilePtr = Marshal.StringToHGlobalUni(ssid);
            var parameters = new WLAN_CONNECTION_PARAMETERS_NATIVE
            {
                wlanConnectionMode = WLAN_CONNECTION_MODE.Profile,
                strProfile = profilePtr,
                pDot11Ssid = ssidPtr,
                pDesiredBssidList = bssidPtr,
                dot11BssType = DOT11_BSS_TYPE.Any,
                dwFlags = 0
            };

            var tcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            _connectTcs = tcs;

            ThrowOnError(WlanConnect(_clientHandle, ref interfaceId, ref parameters, IntPtr.Zero), "WlanConnect");

            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(TimeSpan.FromSeconds(20));
            using var reg = timeoutCts.Token.Register(() => tcs.TrySetCanceled(timeoutCts.Token));
            var completed = await tcs.Task.ConfigureAwait(false);
            if (!completed)
            {
                throw new InvalidOperationException("Connection attempt failed.");
            }
        }
        finally
        {
            _connectTcs = null;
            Marshal.FreeHGlobal(ssidPtr);
            if (bssidPtr != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(bssidPtr);
            }
            // Free unmanaged profile string used in native parameters.
            Marshal.FreeHGlobal(profilePtr);
        }
    }

    public async Task<IReadOnlyList<AvailableNetwork>> ScanAsync(Guid interfaceId, CancellationToken cancellationToken)
    {
        await PerformScanAsync(interfaceId, cancellationToken).ConfigureAwait(false);
        return GetAvailableNetworks(interfaceId);
    }

    public async Task<IReadOnlyList<BssEntry>> ScanBssAsync(Guid interfaceId, CancellationToken cancellationToken)
    {
        await PerformScanAsync(interfaceId, cancellationToken).ConfigureAwait(false);
        return GetBssList(interfaceId);
    }

    private async Task PerformScanAsync(Guid interfaceId, CancellationToken cancellationToken)
    {
        EnsureNotDisposed();

        var tcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        _scanTcs = tcs;
        try
        {
            ThrowOnError(WlanScan(_clientHandle, ref interfaceId, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero), "WlanScan");

            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(TimeSpan.FromSeconds(15));
            using var reg = timeoutCts.Token.Register(() => tcs.TrySetCanceled(timeoutCts.Token));


            var completed = await tcs.Task.ConfigureAwait(false);
            if (!completed)
            {
                throw new InvalidOperationException("Scan attempt failed.");
            }
        }
        finally
        {
            _scanTcs = null;
        }
    }

    private IReadOnlyList<AvailableNetwork> GetAvailableNetworks(Guid interfaceId)
    {
        ThrowOnError(WlanGetAvailableNetworkList(_clientHandle, ref interfaceId, 0, IntPtr.Zero, out var listPtr), "WlanGetAvailableNetworkList");
        try
        {
            var header = Marshal.PtrToStructure<WLAN_AVAILABLE_NETWORK_LIST_HEADER>(listPtr);
            var itemPtr = IntPtr.Add(listPtr, Marshal.SizeOf<WLAN_AVAILABLE_NETWORK_LIST_HEADER>());
            var result = new List<AvailableNetwork>((int)header.dwNumberOfItems);
            for (var i = 0; i < header.dwNumberOfItems; i++)
            {
                var net = Marshal.PtrToStructure<WLAN_AVAILABLE_NETWORK>(itemPtr);
                result.Add(new AvailableNetwork(
                    WlanNative.SsidToString(net.dot11Ssid),
                    net.dot11BssType,
                    net.wlanSignalQuality,
                    net.bSecurityEnabled,
                    net.uNumberOfBssids));

                itemPtr = IntPtr.Add(itemPtr, Marshal.SizeOf<WLAN_AVAILABLE_NETWORK>());
            }

            return result;
        }
        finally
        {
            WlanFreeMemory(listPtr);
        }
    }

    private IReadOnlyList<BssEntry> GetBssList(Guid interfaceId)
    {
        ThrowOnError(WlanGetNetworkBssList(_clientHandle, ref interfaceId, IntPtr.Zero, DOT11_BSS_TYPE.Any, false, IntPtr.Zero, out var listPtr), "WlanGetNetworkBssList");
        try
        {
            var header = Marshal.PtrToStructure<WLAN_BSS_LIST_HEADER>(listPtr);
            var itemPtr = IntPtr.Add(listPtr, Marshal.SizeOf<WLAN_BSS_LIST_HEADER>());
            var result = new List<BssEntry>((int)header.dwNumberOfItems);
            for (var i = 0; i < header.dwNumberOfItems; i++)
            {
                var entry = Marshal.PtrToStructure<WLAN_BSS_ENTRY>(itemPtr);
                result.Add(new BssEntry(
                    WlanNative.SsidToString(entry.dot11Ssid),
                    WlanNative.MacToString(entry.dot11Bssid.Address),
                    entry.lRssi,
                    entry.uLinkQuality,
                    entry.ulChCenterFrequency,
                    entry.dot11BssType,
                    entry.dot11BssPhyType));

                itemPtr = IntPtr.Add(itemPtr, Marshal.SizeOf<WLAN_BSS_ENTRY>());
            }

            return result;
        }
        finally
        {
            WlanFreeMemory(listPtr);
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        if (_clientHandle != IntPtr.Zero)
        {
            WlanCloseHandle(_clientHandle, IntPtr.Zero);
        }
    }

    private void EnsureNotDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(WlanClient));
        }
    }

    private void OnNotification(ref WLAN_NOTIFICATION_DATA notificationData, IntPtr context)
    {
        if (notificationData.NotificationSource != WLAN_NOTIFICATION_SOURCE.ACM)
        {
            return;
        }

        var code = (WLAN_NOTIFICATION_ACM)notificationData.NotificationCode;
        switch (code)
        {
            case WLAN_NOTIFICATION_ACM.ConnectionComplete:
                var success = TryGetConnectionSucceeded(notificationData, out var reasonCode);
                if (!success)
                {
                    Console.WriteLine($"[{DateTime.Now:yyyyMMdd HH:mm:ss}] Connection completed with failure reason {reasonCode} (0x{(uint)reasonCode:X}).");
                }
                else
                {
                    Console.WriteLine($"[{DateTime.Now:yyyyMMdd HH:mm:ss}] Connection completed successfully.");
                }
                _connectTcs?.TrySetResult(success);
                break;
            case WLAN_NOTIFICATION_ACM.ConnectionAttemptFail:
                var hasReason = TryGetConnectionReason(notificationData, out var failReason);
                var reasonText = hasReason ? $"{failReason} (0x{(uint)failReason:X})" : "unknown";
                Console.WriteLine($"[{DateTime.Now:yyyyMMdd HH:mm:ss}] Connection attempt failed: {reasonText}.");
                break;
            case WLAN_NOTIFICATION_ACM.Disconnected:
                _connectTcs?.TrySetResult(false);
                break;
            case WLAN_NOTIFICATION_ACM.ScanComplete:
                _scanTcs?.TrySetResult(true);
                break;
            case WLAN_NOTIFICATION_ACM.ScanFail:
                _scanTcs?.TrySetResult(false);
                break;
        }
    }

    private static bool TryGetConnectionSucceeded(WLAN_NOTIFICATION_DATA notificationData, out WLAN_REASON_CODE reasonCode)
    {
        var hasReason = TryGetConnectionReason(notificationData, out reasonCode);
        return hasReason && reasonCode == WLAN_REASON_CODE.SUCCESS;
    }

    private static bool TryGetConnectionReason(WLAN_NOTIFICATION_DATA notificationData, out WLAN_REASON_CODE reasonCode)
    {
        reasonCode = WLAN_REASON_CODE.SUCCESS;

        if (notificationData.pData == IntPtr.Zero)
        {
            return false;
        }

        var expectedSize = Marshal.SizeOf<WLAN_CONNECTION_NOTIFICATION_DATA>();
        if (notificationData.dwDataSize < expectedSize)
        {
            return false;
        }

        var data = Marshal.PtrToStructure<WLAN_CONNECTION_NOTIFICATION_DATA>(notificationData.pData);
        reasonCode = data.wlanReasonCode;
        return true;
    }

    private static void ThrowOnError(int result, string operation)
    {
        if (result != 0)
        {
            throw new Win32Exception(result, $"{operation} failed with error {result}");
        }
    }

    #region Native bindings

    private const string WlanApi = "wlanapi.dll";

    private delegate void WlanNotificationCallback(ref WLAN_NOTIFICATION_DATA notificationData, IntPtr context);

    [LibraryImport(WlanApi, SetLastError = true)]
    private static partial int WlanOpenHandle(
        uint dwClientVersion,
        IntPtr pReserved,
        out uint pdwNegotiatedVersion,
        out IntPtr phClientHandle);

    [LibraryImport(WlanApi, SetLastError = true)]
    private static partial int WlanCloseHandle(
        IntPtr hClientHandle,
        IntPtr pReserved);

    [LibraryImport(WlanApi, SetLastError = true)]
    private static partial int WlanEnumInterfaces(
        IntPtr hClientHandle,
        IntPtr pReserved,
        out IntPtr ppInterfaceList);

    [LibraryImport(WlanApi, SetLastError = true)]
    private static partial void WlanFreeMemory(IntPtr pMemory);

    [LibraryImport(WlanApi, SetLastError = true)]
    private static partial int WlanRegisterNotification(
        IntPtr hClientHandle,
        WLAN_NOTIFICATION_SOURCE dwNotifSource,
        [MarshalAs(UnmanagedType.Bool)] bool bIgnoreDuplicate,
        WlanNotificationCallback funcCallback,
        IntPtr pCallbackContext,
        IntPtr pReserved,
        out WLAN_NOTIFICATION_SOURCE pdwPrevNotifSource);

    [LibraryImport(WlanApi, SetLastError = true)]
    private static partial int WlanConnect(
        IntPtr hClientHandle,
        ref Guid pInterfaceGuid,
        ref WLAN_CONNECTION_PARAMETERS_NATIVE pConnectionParameters,
        IntPtr pReserved);

    [LibraryImport(WlanApi, SetLastError = true)]
    private static partial int WlanScan(
        IntPtr hClientHandle,
        ref Guid pInterfaceGuid,
        IntPtr pDot11Ssid,
        IntPtr pIeData,
        IntPtr pReserved);

    [LibraryImport(WlanApi, SetLastError = true)]
    private static partial int WlanGetAvailableNetworkList(
        IntPtr hClientHandle,
        ref Guid pInterfaceGuid,
        uint dwFlags,
        IntPtr pReserved,
        out IntPtr ppAvailableNetworkList);

    [LibraryImport(WlanApi, SetLastError = true)]
    private static partial int WlanGetNetworkBssList(
        IntPtr hClientHandle,
        ref Guid pInterfaceGuid,
        IntPtr pDot11Ssid,
        DOT11_BSS_TYPE dot11BssType,
        [MarshalAs(UnmanagedType.Bool)] bool bSecurityEnabled,
        IntPtr pReserved,
        out IntPtr ppWlanBssList);

    #endregion
}

internal static class WlanNative
{
    public static DOT11_SSID CreateSsid(string ssid)
    {
        var ssidBytes = Encoding.ASCII.GetBytes(ssid);
        if (ssidBytes.Length > 32)
        {
            throw new ArgumentException("SSID length must be 32 bytes or less.", nameof(ssid));
        }

        var buffer = new byte[32];
        Array.Copy(ssidBytes, buffer, ssidBytes.Length);

        return new DOT11_SSID
        {
            SSIDLength = (uint)ssidBytes.Length,
            SSID = buffer
        };
    }

    public static IntPtr CreateBssidList(string bssid)
    {
        var macBytes = ParseMac(bssid);
        var list = new DOT11_BSSID_LIST
        {
            Header = new NDIS_OBJECT_HEADER
            {
                Type = 0,
                Revision = 1,
                Size = (ushort)Marshal.SizeOf<DOT11_BSSID_LIST>()
            },
            NumOfEntries = 1,
            TotalNumOfEntries = 1,
            BssidEntry = new DOT11_BSSID_ENTRY
            {
                Bssid = new DOT11_MAC_ADDRESS { Address = macBytes },
                BssType = DOT11_BSS_TYPE.Any,
                PhyType = DOT11_PHY_TYPE.Unknown,
                Reserved = new byte[16]
            }
        };

        var ptr = Marshal.AllocHGlobal(Marshal.SizeOf<DOT11_BSSID_LIST>());
        Marshal.StructureToPtr(list, ptr, false);
        return ptr;
    }

    public static string SsidToString(DOT11_SSID ssid)
    {
        if (ssid.SSIDLength == 0)
        {
            return string.Empty;
        }

        var length = (int)Math.Min(ssid.SSIDLength, (uint)ssid.SSID.Length);
        return Encoding.ASCII.GetString(ssid.SSID, 0, length);
    }

    public static string MacToString(byte[] address)
    {
        if (address is null || address.Length < 6)
        {
            return string.Empty;
        }

        return string.Create(17, address, (span, source) =>
        {
            span[0] = GetHex(source[0] >> 4);
            span[1] = GetHex(source[0]);
            span[2] = ':';
            span[3] = GetHex(source[1] >> 4);
            span[4] = GetHex(source[1]);
            span[5] = ':';
            span[6] = GetHex(source[2] >> 4);
            span[7] = GetHex(source[2]);
            span[8] = ':';
            span[9] = GetHex(source[3] >> 4);
            span[10] = GetHex(source[3]);
            span[11] = ':';
            span[12] = GetHex(source[4] >> 4);
            span[13] = GetHex(source[4]);
            span[14] = ':';
            span[15] = GetHex(source[5] >> 4);
            span[16] = GetHex(source[5]);
        });
    }

    private static char GetHex(int value) => (char)((value & 0xF) > 9 ? 'A' + ((value & 0xF) - 10) : '0' + (value & 0xF));

    private static byte[] ParseMac(string bssid)
    {
        var normalized = bssid.Replace("-", string.Empty).Replace(":", string.Empty);
        if (normalized.Length != 12)
        {
            throw new ArgumentException("BSSID must contain 12 hexadecimal characters.", nameof(bssid));
        }

        var bytes = new byte[6];
        for (var i = 0; i < 6; i++)
        {
            bytes[i] = Convert.ToByte(normalized.Substring(i * 2, 2), 16);
        }

        return bytes;
    }
}

#region Native types

internal sealed record AvailableNetwork(string SSID, DOT11_BSS_TYPE BssType, uint SignalQuality, bool SecurityEnabled, uint BssCount);
internal sealed record BssEntry(string Ssid, string Bssid, int Rssi, uint LinkQuality, uint FrequencyKhz, DOT11_BSS_TYPE BssType, DOT11_PHY_TYPE PhyType);

[StructLayout(LayoutKind.Sequential)]
internal struct WLAN_INTERFACE_INFO_LIST_HEADER
{
    public uint dwNumberOfItems;
    public uint dwIndex;
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
internal struct WLAN_INTERFACE_INFO
{
    public Guid InterfaceGuid;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string strInterfaceDescription;
    public WLAN_INTERFACE_STATE isState;
}

internal enum WLAN_INTERFACE_STATE
{
    NotReady = 0,
    Connected = 1,
    AdHocNetworkFormed = 2,
    Disconnecting = 3,
    Disconnected = 4,
    Associating = 5,
    Discovering = 6,
    Authenticating = 7
}

[StructLayout(LayoutKind.Sequential)]
internal struct WLAN_NOTIFICATION_DATA
{
    public WLAN_NOTIFICATION_SOURCE NotificationSource;
    public int NotificationCode;
    public Guid InterfaceGuid;
    public int dwDataSize;
    public IntPtr pData;
}

[Flags]
internal enum WLAN_NOTIFICATION_SOURCE
{
    None = 0,
    Onex = 0x00000004,
    ACM = 0x00000008,
    MSM = 0x00000010,
    Security = 0x00000020,
    IHV = 0x00000040,
    All = 0x0000FFFF
}

internal enum WLAN_NOTIFICATION_ACM
{
    AutoconfEnabled = 1,
    AutoconfDisabled,
    BackgroundScanEnabled,
    BackgroundScanDisabled,
    BssTypeChange,
    PowerSettingChange,
    ScanComplete,
    ScanFail,
    ConnectionStart,
    ConnectionComplete,
    ConnectionAttemptFail,
    FilterListChange,
    InterfaceArrival,
    InterfaceRemoval,
    ProfileChange,
    ProfileNameChange,
    ProfilesExhausted,
    NetworkNotAvailable,
    NetworkAvailable,
    Disconnecting,
    Disconnected,
    AdhocNetworkStateChange
}

internal enum WLAN_REASON_CODE : uint
{
    SUCCESS = 0
}

internal enum WLAN_CONNECTION_MODE
{
    Profile = 0,
    TemporaryProfile,
    DiscoverySecure,
    DiscoveryUnsecure,
    Auto,
    Invalid
}

[StructLayout(LayoutKind.Sequential)]
internal struct WLAN_CONNECTION_PARAMETERS
{
    public WLAN_CONNECTION_MODE wlanConnectionMode;
    [MarshalAs(UnmanagedType.LPWStr)]
    public string? strProfile;
    public IntPtr pDot11Ssid;
    public IntPtr pDesiredBssidList;
    public DOT11_BSS_TYPE dot11BssType;
    public uint dwFlags;
}

[StructLayout(LayoutKind.Sequential)]
internal struct WLAN_CONNECTION_PARAMETERS_NATIVE
{
    public WLAN_CONNECTION_MODE wlanConnectionMode;
    public IntPtr strProfile;
    public IntPtr pDot11Ssid;
    public IntPtr pDesiredBssidList;
    public DOT11_BSS_TYPE dot11BssType;
    public uint dwFlags;
}

internal enum DOT11_BSS_TYPE : uint
{
    Infrastructure = 1,
    Independent = 2,
    Any = 3
}

[StructLayout(LayoutKind.Sequential)]
internal struct WLAN_AVAILABLE_NETWORK_LIST_HEADER
{
    public uint dwNumberOfItems;
    public uint dwIndex;
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
internal struct WLAN_AVAILABLE_NETWORK
{
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string strProfileName;
    public DOT11_SSID dot11Ssid;
    public DOT11_BSS_TYPE dot11BssType;
    public uint uNumberOfBssids;
    [MarshalAs(UnmanagedType.Bool)]
    public bool bNetworkConnectable;
    public uint wlanNotConnectableReason;
    public uint uNumberOfPhyTypes;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
    public DOT11_PHY_TYPE[] dot11PhyTypes;
    [MarshalAs(UnmanagedType.Bool)]
    public bool bMorePhyTypes;
    public uint wlanSignalQuality;
    [MarshalAs(UnmanagedType.Bool)]
    public bool bSecurityEnabled;
    public DOT11_AUTH_ALGORITHM dot11DefaultAuthAlgorithm;
    public DOT11_CIPHER_ALGORITHM dot11DefaultCipherAlgorithm;
    public uint dwFlags;
    public uint dwReserved;
}

[StructLayout(LayoutKind.Sequential)]
internal struct DOT11_SSID
{
    public uint SSIDLength;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
    public byte[] SSID;
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
internal struct WLAN_CONNECTION_NOTIFICATION_DATA
{
    public WLAN_CONNECTION_MODE wlanConnectionMode;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string strProfileName;
    public DOT11_SSID dot11Ssid;
    public DOT11_BSS_TYPE dot11BssType;
    [MarshalAs(UnmanagedType.Bool)]
    public bool bSecurityEnabled;
    public WLAN_REASON_CODE wlanReasonCode;
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
internal struct NDIS_OBJECT_HEADER
{
    public byte Type;
    public byte Revision;
    public ushort Size;
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
internal struct DOT11_MAC_ADDRESS
{
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
    public byte[] Address;
}

internal enum DOT11_PHY_TYPE : uint
{
    Unknown = 0,
    Any = 0xFFFFFFFF
}

internal enum DOT11_AUTH_ALGORITHM : uint
{
    IEEE80211_Open = 1,
    IEEE80211_SharedKey = 2,
    WPA = 3,
    WPA_PSK = 4,
    WPA_None = 5,
    RSNA = 6,
    RSNA_PSK = 7,
    WPA3 = 8,
    WPA3_SAE = 9,
    OWE = 10,
    WPA3_192 = 11,
    WPA3_ENT = 12,
    WPA3_ENT_192 = 13,
    Unknown = 0xFFFFFFFF
}

internal enum DOT11_CIPHER_ALGORITHM : uint
{
    None = 0x00,
    WEP40 = 0x01,
    TKIP = 0x02,
    CCMP = 0x04,
    WEP104 = 0x05,
    BIP = 0x06,
    GCMP = 0x08,
    GCMP_256 = 0x09,
    BIP_GMAC_128 = 0x0a,
    BIP_GMAC_256 = 0x0b,
    BIP_CMAC_256 = 0x0c,
    WEP = 0x100,
    IHV_START = 0x80000000,
    IHV_END = 0xffffffff
}

[StructLayout(LayoutKind.Sequential)]
internal struct WLAN_BSS_LIST_HEADER
{
    public uint dwTotalSize;
    public uint dwNumberOfItems;
}

[StructLayout(LayoutKind.Sequential)]
internal struct WLAN_BSS_ENTRY
{
    public DOT11_SSID dot11Ssid;
    public uint uPhyId;
    public DOT11_MAC_ADDRESS dot11Bssid;
    public DOT11_BSS_TYPE dot11BssType;
    public DOT11_PHY_TYPE dot11BssPhyType;
    public int lRssi;
    public uint uLinkQuality;
    [MarshalAs(UnmanagedType.Bool)]
    public bool bInRegDomain;
    public ushort usBeaconPeriod;
    public ulong ullTimestamp;
    public ulong ullHostTimestamp;
    public ushort usCapabilityInformation;
    public uint ulChCenterFrequency;
    public WLAN_RATE_SET wlanRateSet;
    public uint ulIeOffset;
    public uint ulIeSize;
}

[StructLayout(LayoutKind.Sequential)]
internal struct WLAN_RATE_SET
{
    public uint uRateSetLength;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 126)]
    public ushort[] ucRateSet;
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
internal struct DOT11_BSSID_ENTRY
{
    public DOT11_MAC_ADDRESS Bssid;
    public DOT11_BSS_TYPE BssType;
    public DOT11_PHY_TYPE PhyType;
    public int Rssi;
    public uint LinkQuality;
    [MarshalAs(UnmanagedType.Bool)]
    public bool InRegDomain;
    public ushort BeaconPeriod;
    public ulong Timestamp;
    public ulong HostTimestamp;
    public ushort CapabilityInformation;
    public uint ChCenterFrequency;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
    public byte[] Reserved;
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
internal struct DOT11_BSSID_LIST
{
    public NDIS_OBJECT_HEADER Header;
    public uint NumOfEntries;
    public uint TotalNumOfEntries;
    public DOT11_BSSID_ENTRY BssidEntry;
}

#endregion
