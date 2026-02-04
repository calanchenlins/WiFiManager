using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

/// <summary>
/// A SafeHandle-based wrapper for native memory allocated via <see cref="Marshal.AllocHGlobal(int)"/>.
/// Ensures proper cleanup even during exceptions.
/// </summary>
/// <remarks>
/// <para>
/// This class inherits from SafeHandle to leverage the CLR's critical finalization guarantees,
/// ensuring native memory is freed even if the finalizer thread is aborted.
/// </para>
/// <para>
/// <b>Important:</b> Only use this class for memory allocated with <see cref="Marshal.AllocHGlobal(int)"/>.
/// Do NOT use for memory returned by Windows APIs (e.g., WlanFreeMemory) as those require different deallocation.
/// </para>
/// </remarks>
internal sealed class SafeNativeMemory : SafeHandle
{
    public SafeNativeMemory() : base(IntPtr.Zero, ownsHandle: true)
    {
    }

    public SafeNativeMemory(int size) : base(IntPtr.Zero, ownsHandle: true)
    {
        if (size > 0)
        {
            SetHandle(Marshal.AllocHGlobal(size));
        }
    }

    public override bool IsInvalid => handle == IntPtr.Zero;

    public IntPtr Pointer => handle;

    /// <summary>
    /// Takes ownership of memory allocated via <see cref="Marshal.AllocHGlobal(int)"/>.
    /// Frees any previously held memory before taking the new pointer.
    /// </summary>
    /// <param name="ptr">Pointer to memory allocated with <see cref="Marshal.AllocHGlobal(int)"/>. Must not be from other allocators.</param>
    public void TakeOwnership(IntPtr ptr)
    {
        if (!IsInvalid)
        {
            Marshal.FreeHGlobal(handle);
        }
        SetHandle(ptr);
    }

    protected override bool ReleaseHandle()
    {
        if (!IsInvalid)
        {
            Marshal.FreeHGlobal(handle);
            SetHandle(IntPtr.Zero);
        }
        return true;
    }
}

/// <summary>
/// Provides a managed wrapper for Windows WLAN API operations.
/// </summary>
/// <remarks>
/// This class manages native WLAN resources and must be disposed when no longer needed.
/// It supports Wi-Fi interface enumeration, connection management, and network scanning.
/// </remarks>
internal sealed partial class WlanClient : IDisposable
{
    private const uint ClientVersion = 2;
    private const int ERROR_INVALID_STATE = 5023;
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(20);
    private static readonly TimeSpan ScanTimeout = TimeSpan.FromSeconds(15);

    private readonly IntPtr _clientHandle;
    // Must keep a reference to the callback delegate to prevent GC from collecting it while native code holds a pointer.
    private readonly WlanNotificationCallback _notificationCallback;
    private readonly EventHandler _processExitHandler;
    private readonly UnhandledExceptionEventHandler _unhandledExceptionHandler;
    private TaskCompletionSource<bool>? _connectTcs;
    private TaskCompletionSource<bool>? _scanTcs;
    private int _disposed; // 0 = not disposed, 1 = disposed

    public WlanClient()
    {
        ThrowOnError(WlanOpenHandle(ClientVersion, IntPtr.Zero, out var negotiatedVersion, out _clientHandle), "WlanOpenHandle");
        try
        {
            _notificationCallback = OnNotification;
            ThrowOnError(WlanRegisterNotification(_clientHandle, WLAN_NOTIFICATION_SOURCE.ACM, false, _notificationCallback, IntPtr.Zero, IntPtr.Zero, out _), "WlanRegisterNotification");
            _processExitHandler = (_, __) => Dispose();
            _unhandledExceptionHandler = (_, __) => Dispose();
            AppDomain.CurrentDomain.ProcessExit += _processExitHandler;
            AppDomain.CurrentDomain.UnhandledException += _unhandledExceptionHandler;
        }
        catch
        {
            WlanCloseHandle(_clientHandle, IntPtr.Zero);
            throw;
        }
    }

    ~WlanClient()
    {
        Dispose();
    }

    /// <summary>
    /// Enumerates all available Wi-Fi interfaces on the system.
    /// </summary>
    /// <returns>A read-only list of available Wi-Fi interfaces.</returns>
    /// <exception cref="ObjectDisposedException">Thrown when the client has been disposed.</exception>
    /// <exception cref="Win32Exception">Thrown when the native API call fails.</exception>
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

    /// <summary>
    /// Asynchronously connects to a Wi-Fi network using the specified SSID and optional BSSID.
    /// </summary>
    /// <param name="interfaceId">The GUID of the Wi-Fi interface to use for the connection.</param>
    /// <param name="ssid">The SSID of the network to connect to.</param>
    /// <param name="bssid">The optional BSSID (MAC address) of the specific access point to connect to.</param>
    /// <param name="cancellationToken">A token to cancel the connection attempt.</param>
    /// <returns>A task that completes when the connection is established or fails.</returns>
    /// <exception cref="ArgumentException">Thrown when the SSID is null or empty.</exception>
    /// <exception cref="ObjectDisposedException">Thrown when the client has been disposed.</exception>
    /// <exception cref="InvalidOperationException">Thrown when the connection attempt fails.</exception>
    /// <exception cref="OperationCanceledException">Thrown when the operation is canceled or times out.</exception>
    public async Task ConnectAsync(Guid interfaceId, string ssid, string? bssid, CancellationToken cancellationToken)
    {
        EnsureNotDisposed();

        if (string.IsNullOrWhiteSpace(ssid))
        {
            throw new ArgumentException("SSID cannot be empty.", nameof(ssid));
        }

        var ssidStruct = WlanNative.CreateSsid(ssid);
        using var ssidMem = new SafeNativeMemory(Marshal.SizeOf<DOT11_SSID>());
        using var bssidMem = new SafeNativeMemory();
        // Note: profileMem takes ownership of memory from Marshal.StringToHGlobalUni,
        // which internally uses AllocHGlobal, so SafeNativeMemory can safely free it.
        using var profileMem = new SafeNativeMemory();
        TaskCompletionSource<bool>? tcs = null;

        try
        {
            Marshal.StructureToPtr(ssidStruct, ssidMem.Pointer, false);

            if (!string.IsNullOrWhiteSpace(bssid))
            {
                bssidMem.TakeOwnership(WlanNative.CreateBssidList(bssid!));
            }

            profileMem.TakeOwnership(Marshal.StringToHGlobalUni(ssid));
            var parameters = new WLAN_CONNECTION_PARAMETERS_NATIVE(
                WLAN_CONNECTION_MODE.Profile,
                profileMem.Pointer,
                ssidMem.Pointer,
                bssidMem.Pointer,
                DOT11_BSS_TYPE.Any,
                0);

            tcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            // Set TCS before calling API to avoid race condition where notification arrives before TCS is set
            var oldTcs = Interlocked.Exchange(ref _connectTcs, tcs);
            oldTcs?.TrySetCanceled();

            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(ConnectTimeout);
            using var reg = timeoutCts.Token.Register(() => tcs.TrySetCanceled(timeoutCts.Token));

            ThrowOnError(WlanConnect(_clientHandle, ref interfaceId, ref parameters, IntPtr.Zero), "WlanConnect");

            var completed = await tcs.Task.ConfigureAwait(false);
            if (!completed)
            {
                throw new InvalidOperationException("Connection attempt failed.");
            }
        }
        finally
        {
            // Only clear if we set it (avoids clearing a newer TCS set by another call)
            if (tcs != null)
            {
                Interlocked.CompareExchange(ref _connectTcs, null, tcs);
            }
            // Native memory is automatically freed by SafeNativeMemory.Dispose()
        }
    }

    /// <summary>
    /// Gets information about the current Wi-Fi connection on the specified interface.
    /// </summary>
    /// <param name="interfaceId">The GUID of the Wi-Fi interface to query.</param>
    /// <returns>
    /// A <see cref="CurrentConnectionInfo"/> containing connection details.
    /// If not connected, <see cref="CurrentConnectionInfo.IsConnected"/> will be <c>false</c>.
    /// </returns>
    /// <exception cref="ObjectDisposedException">Thrown when the client has been disposed.</exception>
    /// <exception cref="Win32Exception">Thrown when the native API call fails.</exception>
    public CurrentConnectionInfo GetCurrentConnection(Guid interfaceId)
    {
        EnsureNotDisposed();

        var result = WlanQueryInterface(
            _clientHandle,
            ref interfaceId,
            WLAN_INTF_OPCODE.CurrentConnection,
            IntPtr.Zero,
            out var dataSize,
            out var dataPtr,
            out _);

        // ERROR_INVALID_STATE means not connected
        if (result == ERROR_INVALID_STATE)
        {
            return new CurrentConnectionInfo(false, null, null, 0);
        }

        if (result != 0)
        {
            throw new Win32Exception(result, $"WlanQueryInterface failed with error {result}");
        }

        try
        {
            var attrs = Marshal.PtrToStructure<WLAN_CONNECTION_ATTRIBUTES>(dataPtr);
            var ssid = WlanNative.SsidToString(attrs.wlanAssociationAttributes.dot11Ssid);
            var bssid = WlanNative.MacToString(attrs.wlanAssociationAttributes.dot11Bssid);
            var signalQuality = attrs.wlanAssociationAttributes.wlanSignalQuality;
            return new CurrentConnectionInfo(true, ssid, bssid, signalQuality);
        }
        finally
        {
            WlanFreeMemory(dataPtr);
        }
    }

    /// <summary>
    /// Triggers a Wi-Fi scan and returns the list of available networks.
    /// </summary>
    /// <param name="interfaceId">The GUID of the Wi-Fi interface to use for scanning.</param>
    /// <param name="cancellationToken">A token to cancel the scan operation.</param>
    /// <returns>A read-only list of available Wi-Fi networks grouped by SSID.</returns>
    /// <exception cref="ObjectDisposedException">Thrown when the client has been disposed.</exception>
    /// <exception cref="InvalidOperationException">Thrown when the scan fails.</exception>
    /// <exception cref="OperationCanceledException">Thrown when the operation is canceled or times out.</exception>
    public async Task<IReadOnlyList<AvailableNetwork>> ScanAsync(Guid interfaceId, CancellationToken cancellationToken)
    {
        await PerformScanAsync(interfaceId, cancellationToken).ConfigureAwait(false);
        return GetAvailableNetworks(interfaceId);
    }

    /// <summary>
    /// Triggers a Wi-Fi scan and returns the list of BSS (Basic Service Set) entries.
    /// </summary>
    /// <param name="interfaceId">The GUID of the Wi-Fi interface to use for scanning.</param>
    /// <param name="cancellationToken">A token to cancel the scan operation.</param>
    /// <returns>A read-only list of BSS entries with detailed per-access-point information.</returns>
    /// <exception cref="ObjectDisposedException">Thrown when the client has been disposed.</exception>
    /// <exception cref="InvalidOperationException">Thrown when the scan fails.</exception>
    /// <exception cref="OperationCanceledException">Thrown when the operation is canceled or times out.</exception>
    public async Task<IReadOnlyList<BssEntry>> ScanBssAsync(Guid interfaceId, CancellationToken cancellationToken)
    {
        await PerformScanAsync(interfaceId, cancellationToken).ConfigureAwait(false);
        return GetBssList(interfaceId);
    }

    private async Task PerformScanAsync(Guid interfaceId, CancellationToken cancellationToken)
    {
        EnsureNotDisposed();

        TaskCompletionSource<bool>? tcs = null;
        try
        {
            tcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            // Set TCS before calling API to avoid race condition where notification arrives before TCS is set
            var oldTcs = Interlocked.Exchange(ref _scanTcs, tcs);
            oldTcs?.TrySetCanceled();

            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(ScanTimeout);
            using var reg = timeoutCts.Token.Register(() => tcs.TrySetCanceled(timeoutCts.Token));

            ThrowOnError(WlanScan(_clientHandle, ref interfaceId, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero), "WlanScan");

            var completed = await tcs.Task.ConfigureAwait(false);
            if (!completed)
            {
                throw new InvalidOperationException("Scan attempt failed.");
            }
        }
        finally
        {
            // Only clear if we set it (avoids clearing a newer TCS set by another call)
            if (tcs != null)
            {
                Interlocked.CompareExchange(ref _scanTcs, null, tcs);
            }
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
                    net.uNumberOfBssids,
                    net.dot11DefaultAuthAlgorithm,
                    net.dot11DefaultCipherAlgorithm));

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
                    WlanNative.MacToString(entry.dot11Bssid),
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
        // Thread-safe disposal using Interlocked
        if (Interlocked.CompareExchange(ref _disposed, 1, 0) != 0)
        {
            return;
        }

        GC.SuppressFinalize(this);

        // Close handle first to stop receiving notifications
        if (_clientHandle != IntPtr.Zero)
        {
            WlanCloseHandle(_clientHandle, IntPtr.Zero);
        }

        // Then unregister event handlers
        AppDomain.CurrentDomain.ProcessExit -= _processExitHandler;
        AppDomain.CurrentDomain.UnhandledException -= _unhandledExceptionHandler;
    }

    private void EnsureNotDisposed()
    {
        if (Volatile.Read(ref _disposed) != 0)
        {
            throw new ObjectDisposedException(nameof(WlanClient));
        }
    }

    private void OnNotification(ref WLAN_NOTIFICATION_DATA notificationData, IntPtr context)
    {
        // Skip processing if already disposed to avoid logging during finalization
        if (Volatile.Read(ref _disposed) != 0)
        {
            return;
        }

        if (notificationData.NotificationSource != WLAN_NOTIFICATION_SOURCE.ACM)
        {
            return;
        }

        var code = (WLAN_NOTIFICATION_ACM)notificationData.NotificationCode;

        switch (code)
        {
            case WLAN_NOTIFICATION_ACM.ConnectionComplete:
                var success = TryGetConnectionSucceeded(notificationData, out var reasonCode);
                var connectTcs = Interlocked.Exchange(ref _connectTcs, null);
                if (connectTcs != null)
                {
                    if (!success)
                    {
                        Logger.Log($"Connection completed with failure reason {reasonCode} (0x{(uint)reasonCode:X}).");
                    }
                    else
                    {
                        Logger.Log("Connection completed successfully.");
                    }
                    connectTcs.TrySetResult(success);
                }
                break;
            case WLAN_NOTIFICATION_ACM.ConnectionAttemptFail:
                var hasReason = TryGetConnectionReason(notificationData, out var failReason);
                var reasonText = hasReason ? $"{failReason} (0x{(uint)failReason:X})" : "unknown";
                Logger.Log($"Connection attempt failed: {reasonText}.");
                break;
            case WLAN_NOTIFICATION_ACM.Disconnected:
                Logger.Log("Connection Disconnected.");
                break;
            case WLAN_NOTIFICATION_ACM.ScanComplete:
                var scanTcs = Interlocked.Exchange(ref _scanTcs, null);
                if (scanTcs != null)
                {
                    Logger.Log("Scan completed.");
                    scanTcs.TrySetResult(true);
                }
                break;
            case WLAN_NOTIFICATION_ACM.ScanFail:
                var scanFailTcs = Interlocked.Exchange(ref _scanTcs, null);
                if (scanFailTcs != null)
                {
                    Logger.Log("Scan failed.");
                    scanFailTcs.TrySetResult(false);
                }
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

    [LibraryImport(WlanApi, SetLastError = true)]
    private static partial int WlanQueryInterface(
        IntPtr hClientHandle,
        ref Guid pInterfaceGuid,
        WLAN_INTF_OPCODE OpCode,
        IntPtr pReserved,
        out int pdwDataSize,
        out IntPtr ppData,
        out WLAN_OPCODE_VALUE_TYPE pWlanOpcodeValueType);

    #endregion
}

internal static class WlanNative
{
    public static DOT11_SSID CreateSsid(string ssid)
    {
        var ssidBytes = Encoding.UTF8.GetBytes(ssid);
        if (ssidBytes.Length > 32)
        {
            throw new ArgumentException("SSID length must be 32 bytes or less when UTF-8 encoded.", nameof(ssid));
        }

        var buffer = new byte[32];
        Array.Copy(ssidBytes, buffer, ssidBytes.Length);

        return new DOT11_SSID((uint)ssidBytes.Length, buffer);
    }

    public static IntPtr CreateBssidList(string bssid)
    {
        ArgumentNullException.ThrowIfNull(bssid);
        var macBytes = ParseMac(bssid);
        // DOT11_BSSID_LIST structure:
        // - NDIS_OBJECT_HEADER (4 bytes)
        // - uNumOfEntries (4 bytes)
        // - uTotalNumOfEntries (4 bytes)
        // - BSSIDs[1] (6 bytes for one MAC address)
        // Total: 18 bytes, but we use Marshal.SizeOf for proper alignment
        var list = new DOT11_BSSID_LIST
        {
            Header = new NDIS_OBJECT_HEADER(0x80, 1, (ushort)Marshal.SizeOf<DOT11_BSSID_LIST>()),  // Type 0x80 = NDIS_OBJECT_TYPE_DEFAULT
            NumOfEntries = 1,
            TotalNumOfEntries = 1,
            BSSIDs = macBytes
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
        var span = ssid.SSID.AsSpan(0, length);

        // Validate UTF-8 encoding; fall back to Latin-1 (ISO-8859-1) if invalid
        // Latin-1 preserves raw bytes as characters, which is better than ASCII for SSIDs with extended characters
        if (System.Text.Unicode.Utf8.IsValid(span))
        {
            // For valid UTF-8, we need to decode properly as char count may differ from byte count
            return Encoding.UTF8.GetString(span);
        }

        // Latin-1: one byte = one char, use string.Create to avoid intermediate allocations
        return string.Create(length, ssid.SSID, static (chars, source) =>
        {
            for (var i = 0; i < chars.Length; i++)
            {
                chars[i] = (char)source[i];
            }
        });
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

    private static byte[] ParseMac(ReadOnlySpan<char> bssid)
    {
        var bytes = new byte[6];
        var byteIndex = 0;
        var nibbleCount = 0;
        byte currentByte = 0;

        foreach (var c in bssid)
        {
            if (c == ':' || c == '-') continue;

            var nibble = c switch
            {
                >= '0' and <= '9' => c - '0',
                >= 'A' and <= 'F' => c - 'A' + 10,
                >= 'a' and <= 'f' => c - 'a' + 10,
                _ => throw new ArgumentException($"Invalid hex character '{c}' in BSSID.", nameof(bssid))
            };

            currentByte = (byte)((currentByte << 4) | nibble);
            if (++nibbleCount == 2)
            {
                if (byteIndex >= 6)
                {
                    throw new ArgumentException("BSSID must contain exactly 12 hexadecimal characters.", nameof(bssid));
                }
                bytes[byteIndex++] = currentByte;
                currentByte = 0;
                nibbleCount = 0;
            }
        }

        if (byteIndex != 6)
        {
            throw new ArgumentException("BSSID must contain exactly 12 hexadecimal characters.", nameof(bssid));
        }

        return bytes;
    }
}

#region Native types

// Naming convention:
// - Native Win32 structs/enums use SCREAMING_SNAKE_CASE (e.g., WLAN_INTERFACE_INFO) to match Windows SDK headers.
// - Managed wrapper types use PascalCase (e.g., AvailableNetwork, BssEntry).

/// <summary>
/// Represents a Wi-Fi network discovered during a scan, grouped by SSID.
/// </summary>
/// <param name="SSID">The Service Set Identifier (network name).</param>
/// <param name="BssType">The BSS type (Infrastructure, Independent, or Any).</param>
/// <param name="SignalQuality">Signal quality as a percentage (0-100).</param>
/// <param name="SecurityEnabled">Indicates whether security is enabled on this network.</param>
/// <param name="BssCount">The number of BSSIDs (access points) broadcasting this SSID.</param>
/// <param name="AuthAlgorithm">The default authentication algorithm used by this network.</param>
/// <param name="CipherAlgorithm">The default cipher algorithm used by this network.</param>
internal sealed record AvailableNetwork(
    string SSID,
    DOT11_BSS_TYPE BssType,
    uint SignalQuality,
    bool SecurityEnabled,
    uint BssCount,
    DOT11_AUTH_ALGORITHM AuthAlgorithm,
    DOT11_CIPHER_ALGORITHM CipherAlgorithm);

/// <summary>
/// Represents a single BSS (Basic Service Set) entry, providing detailed per-access-point information.
/// </summary>
/// <param name="Ssid">The Service Set Identifier (network name).</param>
/// <param name="Bssid">The MAC address of the access point.</param>
/// <param name="Rssi">Received Signal Strength Indicator in dBm (typically -30 to -90).</param>
/// <param name="LinkQuality">Link quality as a percentage (0-100).</param>
/// <param name="FrequencyKhz">The channel center frequency in kHz.</param>
/// <param name="BssType">The BSS type (Infrastructure or Independent).</param>
/// <param name="PhyType">The PHY type indicating the Wi-Fi standard (e.g., HE for Wi-Fi 6).</param>
internal sealed record BssEntry(string Ssid, string Bssid, int Rssi, uint LinkQuality, uint FrequencyKhz, DOT11_BSS_TYPE BssType, DOT11_PHY_TYPE PhyType);

[StructLayout(LayoutKind.Sequential)]
internal readonly struct WLAN_INTERFACE_INFO_LIST_HEADER
{
    public readonly uint dwNumberOfItems;
    public readonly uint dwIndex;
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
    SUCCESS = 0,
    // General codes
    UNKNOWN = 0x00010000,
    RANGE_SIZE = 0x00010000,
    BASE = 0x00010000,
    // AC (Auto Configuration) codes
    AC_BASE = 0x00020000,
    AC_CONNECT_REASON_START = 0x00020000,
    NETWORK_NOT_COMPATIBLE = 0x00020001,
    PROFILE_NOT_COMPATIBLE = 0x00020002,
    NO_AUTO_CONNECTION = 0x00020003,
    NOT_VISIBLE = 0x00020004,
    GP_DENIED = 0x00020005,
    USER_DENIED = 0x00020006,
    BSS_TYPE_NOT_ALLOWED = 0x00020007,
    IN_FAILED_LIST = 0x00020008,
    IN_BLOCKED_LIST = 0x00020009,
    SSID_LIST_TOO_LONG = 0x0002000A,
    CONNECT_CALL_FAIL = 0x0002000B,
    SCAN_CALL_FAIL = 0x0002000C,
    NETWORK_NOT_AVAILABLE = 0x0002000D,
    PROFILE_CHANGED_OR_DELETED = 0x0002000E,
    KEY_MISMATCH = 0x0002000F,
    USER_NOT_RESPOND = 0x00020010,
    AP_PROFILE_NOT_ALLOWED_FOR_CLIENT = 0x00020011,
    AP_PROFILE_NOT_ALLOWED = 0x00020012,
    // MSM (Media Specific Module) codes
    MSM_BASE = 0x00030000,
    MSM_CONNECT_REASON_START = 0x00030000,
    UNSUPPORTED_SECURITY_SET_BY_OS = 0x00030001,
    UNSUPPORTED_SECURITY_SET = 0x00030002,
    BSS_TYPE_UNMATCH = 0x00030003,
    PHY_TYPE_UNMATCH = 0x00030004,
    DATARATE_UNMATCH = 0x00030005,
    // 802.1x codes
    MSMSEC_BASE = 0x00040000
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
internal readonly struct WLAN_CONNECTION_PARAMETERS_NATIVE
{
    public readonly WLAN_CONNECTION_MODE wlanConnectionMode;
    public readonly IntPtr strProfile;
    public readonly IntPtr pDot11Ssid;
    public readonly IntPtr pDesiredBssidList;
    public readonly DOT11_BSS_TYPE dot11BssType;
    public readonly uint dwFlags;

    public WLAN_CONNECTION_PARAMETERS_NATIVE(
        WLAN_CONNECTION_MODE connectionMode,
        IntPtr profile,
        IntPtr ssid,
        IntPtr bssidList,
        DOT11_BSS_TYPE bssType,
        uint flags)
    {
        wlanConnectionMode = connectionMode;
        strProfile = profile;
        pDot11Ssid = ssid;
        pDesiredBssidList = bssidList;
        dot11BssType = bssType;
        dwFlags = flags;
    }
}

internal enum DOT11_BSS_TYPE : uint
{
    Infrastructure = 1,
    Independent = 2,
    Any = 3
}

[StructLayout(LayoutKind.Sequential)]
internal readonly struct WLAN_AVAILABLE_NETWORK_LIST_HEADER
{
    public readonly uint dwNumberOfItems;
    public readonly uint dwIndex;
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
internal readonly struct DOT11_SSID
{
    public readonly uint SSIDLength;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
    public readonly byte[] SSID;

    public DOT11_SSID(uint length, byte[] ssid)
    {
        SSIDLength = length;
        SSID = ssid;
    }
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
internal readonly struct NDIS_OBJECT_HEADER
{
    public readonly byte Type;
    public readonly byte Revision;
    public readonly ushort Size;

    public NDIS_OBJECT_HEADER(byte type, byte revision, ushort size)
    {
        Type = type;
        Revision = revision;
        Size = size;
    }
}

internal enum DOT11_PHY_TYPE : uint
{
    Unknown = 0,
    Fhss = 1,           // Frequency-hopping spread-spectrum
    Dsss = 2,           // Direct sequence spread spectrum
    IrBaseband = 3,     // Infrared baseband
    Ofdm = 4,           // 802.11a
    Hrdsss = 5,         // 802.11b
    Erp = 6,            // 802.11g
    Ht = 7,             // 802.11n (Wi-Fi 4)
    Vht = 8,            // 802.11ac (Wi-Fi 5)
    Dmg = 9,            // 802.11ad (60 GHz)
    He = 10,            // 802.11ax (Wi-Fi 6)
    Eht = 11,           // 802.11be (Wi-Fi 7)
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
internal readonly struct WLAN_BSS_LIST_HEADER
{
    public readonly uint dwTotalSize;
    public readonly uint dwNumberOfItems;
}

[StructLayout(LayoutKind.Sequential)]
internal struct WLAN_BSS_ENTRY
{
    public DOT11_SSID dot11Ssid;
    public uint uPhyId;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
    public byte[] dot11Bssid;  // DOT11_MAC_ADDRESS inlined as 6 bytes
    public DOT11_BSS_TYPE dot11BssType;
    public DOT11_PHY_TYPE dot11BssPhyType;
    public int lRssi;
    public uint uLinkQuality;
    [MarshalAs(UnmanagedType.U1)]
    public bool bInRegDomain;  // BOOLEAN is 1 byte, not 4 bytes (BOOL)
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

[StructLayout(LayoutKind.Sequential)]
internal struct DOT11_BSSID_LIST
{
    public NDIS_OBJECT_HEADER Header;
    public uint NumOfEntries;
    public uint TotalNumOfEntries;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
    public byte[] BSSIDs;  // Variable length array of MAC addresses (6 bytes each), we only need 1
}

internal enum WLAN_INTF_OPCODE : uint
{
    AutoconfStart = 0x00000000,
    AutoconfEnabled,
    BackgroundScanEnabled,
    MediaStreamingMode,
    RadioState,
    BssType,
    InterfaceState,
    CurrentConnection,
    ChannelNumber,
    SupportedInfrastructureAuthCipherPairs,
    SupportedAdhocAuthCipherPairs,
    SupportedCountryOrRegionStringList,
    CurrentOperationMode,
    SupportedSafeMode,
    CertifiedSafeMode,
    HostedNetworkCapable,
    ManagementFrameProtectionCapable,
    SecondaryStaInterfaces,
    SecondaryStaSynchronizedConnections,
    AutoconfEnd = 0x0FFFFFFF
}

internal enum WLAN_OPCODE_VALUE_TYPE
{
    QueryOnly = 0,
    SetByGroupPolicy = 1,
    SetByUser = 2,
    Invalid = 3
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
internal struct WLAN_CONNECTION_ATTRIBUTES
{
    public WLAN_INTERFACE_STATE isState;
    public WLAN_CONNECTION_MODE wlanConnectionMode;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string strProfileName;
    public WLAN_ASSOCIATION_ATTRIBUTES wlanAssociationAttributes;
    public WLAN_SECURITY_ATTRIBUTES wlanSecurityAttributes;
}

[StructLayout(LayoutKind.Sequential)]
internal struct WLAN_ASSOCIATION_ATTRIBUTES
{
    public DOT11_SSID dot11Ssid;
    public DOT11_BSS_TYPE dot11BssType;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
    public byte[] dot11Bssid;  // DOT11_MAC_ADDRESS inlined as 6 bytes
    public DOT11_PHY_TYPE dot11PhyType;
    public uint uDot11PhyIndex;
    public uint wlanSignalQuality;
    public uint ulRxRate;
    public uint ulTxRate;
}

[StructLayout(LayoutKind.Sequential)]
internal struct WLAN_SECURITY_ATTRIBUTES
{
    [MarshalAs(UnmanagedType.Bool)]
    public bool bSecurityEnabled;
    [MarshalAs(UnmanagedType.Bool)]
    public bool bOneXEnabled;
    public DOT11_AUTH_ALGORITHM dot11AuthAlgorithm;
    public DOT11_CIPHER_ALGORITHM dot11CipherAlgorithm;
}

/// <summary>
/// Represents the current Wi-Fi connection state and details.
/// </summary>
/// <param name="IsConnected">Indicates whether the interface is currently connected to a network.</param>
/// <param name="Ssid">The SSID of the connected network, or <c>null</c> if not connected.</param>
/// <param name="Bssid">The BSSID (MAC address) of the connected access point, or <c>null</c> if not connected.</param>
/// <param name="SignalQuality">Signal quality as a percentage (0-100), or 0 if not connected.</param>
internal sealed record CurrentConnectionInfo(bool IsConnected, string? Ssid, string? Bssid, uint SignalQuality);

#endregion
