using System.CommandLine;
using System.CommandLine.Parsing;
using System.ComponentModel;
using System.Linq;
using System.Net.NetworkInformation;
using System.Text.Json;
using System.Text.Json.Serialization;

internal static class Logger
{
	public static void Log(string message) => Console.WriteLine($"[{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}] {message}");
}

internal sealed class Program
{
	private const int MaxBackoffSeconds = 60;
	private const int MaxConsecutiveFailures = 10;
	private const int MaxBackoffExponent = 6; // 2^6 = 64, prevents overflow
	private const double JitterFactor = 0.25;

	private static async Task<int> Main(string[] args)
	{
		using var cts = new CancellationTokenSource();
		Console.CancelKeyPress += (_, e) =>
		{
			e.Cancel = true;
			cts.Cancel();
		};

		try
		{
			var rootCommand = CreateRootCommand();
			var parseResult = rootCommand.Parse(args);
			var exitCode = await parseResult.InvokeAsync(null, cts.Token).ConfigureAwait(false);
			return exitCode;
		}
		catch (OperationCanceledException)
		{
			return 0;
		}
	}

	private static RootCommand CreateRootCommand()
	{
		var ssidOption = new Option<string?>("--ssid", "-s")
		{
			Description = "Wi-Fi SSID."
		};

		var bssidOption = new Option<string?>("--bssid", "-b")
		{
			Description = "Wi-Fi BSSID (MAC address)."
		};

		var gatewayOption = new Option<string?>("--gateway", "-g")
		{
			Description = "Gateway IP address to ping."
		};

		var intervalOption = new Option<int?>("--interval", "-i")
		{
			Description = "Ping interval in seconds."
		};

		var configOption = new Option<string?>("--config", "-c")
		{
			Description = "Path to JSON config file."
		};

		var scanModeOption = new Option<ScanMode>("--mode", "-m")
		{
			Description = "Scan mode: network (summary) or bssid (per-BSSID list).",
			DefaultValueFactory = _ => ScanMode.Network
		};

		var interfaceOption = new Option<string?>("--interface", "-n")
		{
			Description = "Target Wi-Fi interface (GUID or name substring)."
		};

		var rootCommand = new RootCommand("WiFiManager - monitor connectivity and scan Wi-Fi networks.");

		var connectCommand = new Command("connect", "Monitor connectivity and reconnect to Wi-Fi.")
		{
			ssidOption,
			bssidOption,
			gatewayOption,
			intervalOption,
			configOption,
			interfaceOption
		};

		connectCommand.SetAction(async (parseResult, cancellationToken) =>
		{
			var options = new ConnectOptions
			{
				SSID = parseResult.GetValue(ssidOption),
				BSSID = parseResult.GetValue(bssidOption),
				Gateway = parseResult.GetValue(gatewayOption),
				Interval = parseResult.GetValue(intervalOption),
				ConfigFile = parseResult.GetValue(configOption),
				Interface = parseResult.GetValue(interfaceOption)
			};

			return await RunConnectAsync(options, cancellationToken).ConfigureAwait(false);
		});

		var scanCommand = new Command("scan", "Trigger a WLAN scan and list visible networks.")
		{
			scanModeOption,
			interfaceOption
		};

		scanCommand.SetAction((parseResult, cancellationToken) =>
		{
			var options = new ScanOptions
			{
				Mode = parseResult.GetValue(scanModeOption),
				Interface = parseResult.GetValue(interfaceOption)
			};

			return RunScanAsync(options, cancellationToken);
		});

		rootCommand.Subcommands.Add(connectCommand);
		rootCommand.Subcommands.Add(scanCommand);

		var showCommand = new Command("show", "Show WLAN information.");
		var showInterfaceCommand = new Command("interface", "List available Wi-Fi interfaces.");

		showInterfaceCommand.SetAction((_, _) => Task.FromResult(RunShowInterface()));
		showCommand.Subcommands.Add(showInterfaceCommand);
		rootCommand.Subcommands.Add(showCommand);

		return rootCommand;
	}

	private static async Task<int> RunConnectAsync(ConnectOptions options, CancellationToken cancellationToken)
	{
		AppConfig config;
		try
		{
			config = await AppConfig.BuildAsync(options, cancellationToken).ConfigureAwait(false);
		}
		catch (Exception ex) when (ex is ArgumentException or FileNotFoundException or JsonException)
		{
			Logger.Log($"Configuration error: {ex.Message}");
			return 1;
		}

		using var wlan = new WlanClient();
		if (!TryResolveInterface(wlan, options.Interface, out var selectedInterface, out var error))
		{
			Logger.Log(error!);
			return 1;
		}

		Logger.Log($"Using interface: {selectedInterface.strInterfaceDescription} (State: {selectedInterface.isState}, GUID: {selectedInterface.InterfaceGuid}).");

		var useGatewayMode = !string.IsNullOrWhiteSpace(config.Gateway);
		if (useGatewayMode)
		{
			Logger.Log($"Gateway mode: Monitoring gateway {config.Gateway} every {config.Interval}s for SSID '{config.SSID}'. Press Ctrl+C to exit.");
		}
		else
		{
			Logger.Log($"BSSID mode: Monitoring connection to SSID '{config.SSID}' (BSSID: {config.BSSID}) every {config.Interval}s. Press Ctrl+C to exit.");
			Logger.Log("WARNING: Windows WLAN AutoConfig may automatically roam to a different BSSID with stronger signal.");
			Logger.Log("         If you experience frequent reconnections, consider disabling auto-connect for this network profile.");
		}

		DateTime? successStart = null;
		DateTime? lastSuccess = null;
		int consecutiveFailures = 0;

		while (!cancellationToken.IsCancellationRequested)
		{
			var (shouldReconnect, disconnectReason) = await CheckConnectivityAsync(
				wlan, selectedInterface.InterfaceGuid, config, useGatewayMode, cancellationToken).ConfigureAwait(false);

			if (!shouldReconnect)
			{
				var now = DateTime.Now;
				successStart ??= now;
				lastSuccess = now;
				consecutiveFailures = 0;
			}
			else
			{
				if (successStart.HasValue && lastSuccess.HasValue)
				{
					Logger.Log($"Connection was healthy from {successStart:yyyy-MM-dd HH:mm:ss.fff} to {lastSuccess:yyyy-MM-dd HH:mm:ss.fff}.");
					successStart = null;
					lastSuccess = null;
				}

				Logger.Log($"{disconnectReason}. Reconnecting...");
				try
				{
					await wlan.ConnectAsync(selectedInterface.InterfaceGuid, config.SSID, config.BSSID, cancellationToken).ConfigureAwait(false);
				}
				catch (Win32Exception ex)
				{
					Logger.Log($"Reconnect failed with Win32 error {ex.NativeErrorCode}: {ex.Message}");
				}
				catch (Exception ex)
				{
					Logger.Log($"Reconnect failed: {ex}");
				}

				consecutiveFailures++;

				if (consecutiveFailures >= MaxConsecutiveFailures)
				{
					Logger.Log($"Reached maximum consecutive failures ({MaxConsecutiveFailures}). Resetting failure count and continuing...");
					consecutiveFailures = 0;
				}
			}

			var waitSeconds = CalculateWaitSeconds(config.Interval, consecutiveFailures);
			if (consecutiveFailures > 0)
			{
				Logger.Log($"Waiting {waitSeconds} seconds before next check (backoff due to {consecutiveFailures} consecutive failure(s), jitter applied)...");
			}
			await Task.Delay(TimeSpan.FromSeconds(waitSeconds), cancellationToken).ConfigureAwait(false);
		}

		return 0;
	}

	private static async Task<int> RunScanAsync(ScanOptions options, CancellationToken cancellationToken)
	{
		using var wlan = new WlanClient();
		if (!TryResolveInterface(wlan, options.Interface, out var selectedInterface, out var error))
		{
			Logger.Log(error!);
			return 1;
		}

		Logger.Log($"Using interface: {selectedInterface.strInterfaceDescription} (State: {selectedInterface.isState}, GUID: {selectedInterface.InterfaceGuid}).");
		Logger.Log(options.Mode == ScanMode.Bssid ? "Scanning for BSS entries..." : "Scanning for available Wi-Fi networks...");

		try
		{
			if (options.Mode == ScanMode.Bssid)
			{
				var bssList = await wlan.ScanBssAsync(selectedInterface.InterfaceGuid, cancellationToken).ConfigureAwait(false);
				if (bssList.Count == 0)
				{
					Logger.Log("No BSS entries found.");
					return 0;
				}

				var ordered = bssList.OrderByDescending(b => b.LinkQuality).ThenByDescending(b => b.Rssi).ToList();
				for (var i = 0; i < ordered.Count; i++)
				{
					var b = ordered[i];
					var freqMhz = b.FrequencyKhz / 1000.0;
					var band = ScanHelpers.GetBand(b.FrequencyKhz) ?? "Unknown";
					Console.WriteLine($"{i + 1}. BSSID: {b.Bssid}, SSID: {b.Ssid}, RSSI: {b.Rssi} dBm, LinkQuality: {b.LinkQuality}%, Freq: {freqMhz:F1} MHz ({band}), Type: {b.BssType}, PHY: {b.PhyType}");
				}
			}
			else
			{
				var networks = await wlan.ScanAsync(selectedInterface.InterfaceGuid, cancellationToken).ConfigureAwait(false);
				if (networks.Count == 0)
				{
					Logger.Log("No networks found.");
					return 0;
				}

				var grouped = networks
					.GroupBy(n => new { n.SSID, n.BssType })
					.Select(g =>
					{
						var strongest = g.OrderByDescending(n => n.SignalQuality).First();
						var totalBssids = g.Sum(n => (int)n.BssCount);
						return new
						{
							strongest.SSID,
							strongest.BssType,
							strongest.SignalQuality,
							strongest.SecurityEnabled,
							BssCount = (uint)totalBssids,
							strongest.AuthAlgorithm,
							strongest.CipherAlgorithm
						};
					})
					.OrderByDescending(n => n.SignalQuality)
					.ToList();

				for (var i = 0; i < grouped.Count; i++)
				{
					var n = grouped[i];
					var authStr = ScanHelpers.GetAuthAlgorithmName(n.AuthAlgorithm);
					var cipherStr = ScanHelpers.GetCipherAlgorithmName(n.CipherAlgorithm);
					var securityInfo = n.SecurityEnabled ? $"{authStr}/{cipherStr}" : "Open";
					Console.WriteLine($"{i + 1}. SSID: {n.SSID}, Signal: {n.SignalQuality}%, Security: {securityInfo}, BSSIDs: {n.BssCount}, Type: {n.BssType}");
				}
			}
		}
		catch (Win32Exception ex)
		{
			Logger.Log($"Scan failed with Win32 error {ex.NativeErrorCode}: {ex.Message}");
			return 1;
		}
		catch (Exception ex)
		{
			Logger.Log($"Scan failed: {ex}");
			return 1;
		}

		return 0;
	}

	private static int RunShowInterface()
	{
		using var wlan = new WlanClient();
		var interfaces = wlan.GetInterfaces();
		if (interfaces.Count == 0)
		{
			Logger.Log("No Wi-Fi interfaces found.");
			return 1;
		}

		for (var i = 0; i < interfaces.Count; i++)
		{
			var iface = interfaces[i];
			Console.WriteLine($"{i + 1}. {iface.strInterfaceDescription} (State: {iface.isState}, GUID: {iface.InterfaceGuid})");
		}

		return 0;
	}

	private static bool TryResolveInterface(WlanClient wlan, string? selector, out WLAN_INTERFACE_INFO selected, out string? error)
	{
		var interfaces = wlan.GetInterfaces();
		if (interfaces.Count == 0)
		{
			selected = default;
			error = "No Wi-Fi interfaces found.";
			return false;
		}

		if (string.IsNullOrWhiteSpace(selector))
		{
			selected = interfaces[0];
			error = null;
			return true;
		}

		var trimmed = selector.Trim();
		var matches = interfaces
			.Where(i => i.InterfaceGuid.ToString().Equals(trimmed, StringComparison.OrdinalIgnoreCase)
					|| i.strInterfaceDescription.Contains(trimmed, StringComparison.OrdinalIgnoreCase))
			.ToArray();

		if (matches.Length == 1)
		{
			selected = matches[0];
			error = null;
			return true;
		}

		selected = default;
		if (matches.Length > 1)
		{
			error = $"Multiple interfaces matched '{selector}'. Please specify the full GUID or a more specific name.";
		}
		else
		{
			error = $"No interface matched '{selector}'.";
		}

		return false;
	}

	/// <summary>
	/// Checks current connectivity status and determines if reconnection is needed.
	/// </summary>
	/// <returns>A tuple indicating whether to reconnect and the reason for disconnection.</returns>
	private static async Task<(bool ShouldReconnect, string? Reason)> CheckConnectivityAsync(
		WlanClient wlan,
		Guid interfaceId,
		AppConfig config,
		bool useGatewayMode,
		CancellationToken cancellationToken)
	{
		if (useGatewayMode)
		{
			// Gateway mode: ping to check connectivity
			var reachable = await NetworkHelper.PingAsync(config.Gateway!, TimeSpan.FromSeconds(2), cancellationToken).ConfigureAwait(false);
			return reachable ? (false, null) : (true, "Gateway unreachable");
		}

		// BSSID mode: check current connection info
		try
		{
			var connInfo = wlan.GetCurrentConnection(interfaceId);
			if (!connInfo.IsConnected)
			{
				return (true, "Not connected to any network");
			}

			if (!string.Equals(connInfo.Ssid, config.SSID, StringComparison.Ordinal))
			{
				return (true, $"Connected to different SSID: '{connInfo.Ssid}' (expected: '{config.SSID}')");
			}

			if (!NetworkHelper.BssidEquals(connInfo.Bssid, config.BSSID))
			{
				return (true, $"Connected to different BSSID: '{connInfo.Bssid}' (expected: '{config.BSSID}')");
			}

			return (false, null);
		}
		catch (Win32Exception ex)
		{
			Logger.Log($"Failed to query connection info: {ex.Message}");
			return (true, "Failed to query connection info");
		}
	}

	/// <summary>
	/// Calculates wait time with exponential backoff and jitter.
	/// </summary>
	/// <param name="baseInterval">Base interval in seconds.</param>
	/// <param name="consecutiveFailures">Number of consecutive failures.</param>
	/// <returns>Wait time in seconds.</returns>
	private static int CalculateWaitSeconds(int baseInterval, int consecutiveFailures)
	{
		// Calculate wait time with exponential backoff on failures (capped to prevent overflow)
		var cappedFailures = Math.Min(consecutiveFailures, MaxBackoffExponent);
		var backoffMultiplier = cappedFailures > 0 ? 1 << (cappedFailures - 1) : 1;
		var baseWaitSeconds = Math.Min(baseInterval * backoffMultiplier, MaxBackoffSeconds);

		// Add jitter (±25%) to prevent thundering herd when multiple devices reconnect simultaneously
		var jitterRange = (int)(baseWaitSeconds * JitterFactor);
		var jitter = jitterRange > 0 ? Random.Shared.Next(-jitterRange, jitterRange + 1) : 0;
		return Math.Max(1, baseWaitSeconds + jitter);
	}
}

internal sealed class ConnectOptions
{
	public string? SSID { get; init; }
	public string? BSSID { get; init; }
	public string? Gateway { get; init; }
	public int? Interval { get; init; }
	public string? ConfigFile { get; init; }
	public string? Interface { get; init; }
}

internal sealed class ScanOptions
{
	public ScanMode Mode { get; init; }
	public string? Interface { get; init; }
}

internal enum ScanMode
{
	Network,
	Bssid
}

internal sealed record AppConfig(string SSID, string? BSSID, string? Gateway, int Interval)
{
	public static async Task<AppConfig> BuildAsync(ConnectOptions options, CancellationToken cancellationToken)
	{
		ConfigFilePayload fileConfig = new();
		if (!string.IsNullOrWhiteSpace(options.ConfigFile))
		{
			var path = options.ConfigFile!;
			if (!File.Exists(path))
			{
				throw new FileNotFoundException($"Config file not found: {path}");
			}

			await using var stream = File.OpenRead(path);
			fileConfig = await JsonSerializer.DeserializeAsync(stream, ConfigFileJsonContext.Default.ConfigFilePayload, cancellationToken).ConfigureAwait(false) ?? new ConfigFilePayload();
		}

		var ssid = options.SSID ?? fileConfig.SSID;
		var bssid = options.BSSID ?? fileConfig.BSSID;
		var gateway = options.Gateway ?? fileConfig.Gateway;
		var interval = options.Interval ?? fileConfig.Interval ?? 5;

		if (string.IsNullOrWhiteSpace(ssid))
		{
			throw new ArgumentException("SSID is required.");
		}

		var hasGateway = !string.IsNullOrWhiteSpace(gateway);
		var hasBssid = !string.IsNullOrWhiteSpace(bssid);

		if (hasGateway && !System.Net.IPAddress.TryParse(gateway, out _))
		{
			throw new ArgumentException($"Invalid gateway IP address format: {gateway}");
		}

		if (hasBssid && !NetworkHelper.IsValidBssid(bssid!))
		{
			throw new ArgumentException($"Invalid BSSID format: {bssid}. Expected format: XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX");
		}

		if (hasGateway && hasBssid)
		{
			throw new ArgumentException("Gateway and BSSID cannot both be specified. Please choose one mode.");
		}

		if (!hasGateway && !hasBssid)
		{
			throw new ArgumentException("Either Gateway or BSSID must be specified.");
		}

		if (interval <= 0)
		{
			throw new ArgumentException("Interval must be positive.");
		}

		return new AppConfig(ssid, bssid, gateway, interval);
	}
}

[JsonSourceGenerationOptions(
	PropertyNameCaseInsensitive = true,
	ReadCommentHandling = JsonCommentHandling.Skip,
	AllowTrailingCommas = true)]
[JsonSerializable(typeof(ConfigFilePayload))]
internal sealed partial class ConfigFileJsonContext : JsonSerializerContext
{
}

internal sealed class ConfigFilePayload
{
	public string? SSID { get; set; }
	public string? BSSID { get; set; }
	public string? Gateway { get; set; }
	public int? Interval { get; set; }
}

internal static class NetworkHelper
{
	/// <summary>
	/// Validates whether a string is a valid BSSID (MAC address) format.
	/// Accepts formats: XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX
	/// </summary>
	public static bool IsValidBssid(ReadOnlySpan<char> bssid)
	{
		var hexCount = 0;
		foreach (var c in bssid)
		{
			if (c == ':' || c == '-')
			{
				continue;
			}

			if (!char.IsAsciiHexDigit(c))
			{
				return false;
			}

			hexCount++;
		}

		return hexCount == 12;
	}

	public static async Task<bool> PingAsync(string host, TimeSpan timeout, CancellationToken cancellationToken)
	{
		using var ping = new Ping();
		try
		{
			// SendPingAsync handles the timeout internally; WaitAsync is only for cancellation support
			var pingTask = ping.SendPingAsync(host, (int)timeout.TotalMilliseconds);
			var reply = await pingTask.WaitAsync(cancellationToken).ConfigureAwait(false);
			return reply.Status == IPStatus.Success;
		}
		catch (PingException)
		{
			return false;
		}
		catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
		{
			// Timeout only, not user cancellation
			return false;
		}
		// Let user cancellation propagate
	}

	/// <summary>
	/// Compares two BSSID strings, ignoring separator differences (colon vs dash).
	/// </summary>
	public static bool BssidEquals(string? bssid1, string? bssid2)
	{
		if (bssid1 is null && bssid2 is null)
		{
			return true;
		}

		if (bssid1 is null || bssid2 is null)
		{
			return false;
		}

		// Use Span<char> to avoid string allocations
		Span<char> buffer1 = stackalloc char[12];
		Span<char> buffer2 = stackalloc char[12];

		if (!TryNormalizeBssid(bssid1, buffer1) || !TryNormalizeBssid(bssid2, buffer2))
		{
			return false;
		}

		return buffer1.SequenceEqual(buffer2);
	}

	private static bool TryNormalizeBssid(ReadOnlySpan<char> bssid, Span<char> destination)
	{
		if (destination.Length < 12)
		{
			return false;
		}

		var destIndex = 0;
		foreach (var c in bssid)
		{
			if (c == ':' || c == '-')
			{
				continue;
			}

			if (destIndex >= 12)
			{
				return false;
			}

			destination[destIndex++] = char.ToUpperInvariant(c);
		}

		return destIndex == 12;
	}
}

internal static class ScanHelpers
{
	public static string? GetBand(uint frequencyKhz) => (frequencyKhz / 1000.0) switch
	{
		0 => null,
		>= 2400 and <= 2500 => "2.4 GHz",
		>= 4900 and < 5925 => "5 GHz",
		>= 5925 and <= 7125 => "6 GHz",
		>= 57000 and <= 71000 => "60 GHz",
		_ => null
	};

	public static string GetAuthAlgorithmName(DOT11_AUTH_ALGORITHM algorithm) => algorithm switch
	{
		DOT11_AUTH_ALGORITHM.IEEE80211_Open => "Open",
		DOT11_AUTH_ALGORITHM.IEEE80211_SharedKey => "WEP-Shared",
		DOT11_AUTH_ALGORITHM.WPA => "WPA-Enterprise",
		DOT11_AUTH_ALGORITHM.WPA_PSK => "WPA-Personal",
		DOT11_AUTH_ALGORITHM.WPA_None => "WPA-None",
		DOT11_AUTH_ALGORITHM.RSNA => "WPA2-Enterprise",
		DOT11_AUTH_ALGORITHM.RSNA_PSK => "WPA2-Personal",
		DOT11_AUTH_ALGORITHM.WPA3 => "WPA3",
		DOT11_AUTH_ALGORITHM.WPA3_SAE => "WPA3-Personal",
		DOT11_AUTH_ALGORITHM.OWE => "OWE",
		DOT11_AUTH_ALGORITHM.WPA3_ENT => "WPA3-Enterprise",
		DOT11_AUTH_ALGORITHM.WPA3_ENT_192 => "WPA3-Enterprise-192",
		_ => algorithm.ToString()
	};

	public static string GetCipherAlgorithmName(DOT11_CIPHER_ALGORITHM algorithm) => algorithm switch
	{
		DOT11_CIPHER_ALGORITHM.None => "None",
		DOT11_CIPHER_ALGORITHM.WEP40 => "WEP40",
		DOT11_CIPHER_ALGORITHM.WEP104 => "WEP104",
		DOT11_CIPHER_ALGORITHM.WEP => "WEP",
		DOT11_CIPHER_ALGORITHM.TKIP => "TKIP",
		DOT11_CIPHER_ALGORITHM.CCMP => "CCMP",
		DOT11_CIPHER_ALGORITHM.GCMP => "GCMP",
		DOT11_CIPHER_ALGORITHM.GCMP_256 => "GCMP-256",
		DOT11_CIPHER_ALGORITHM.BIP => "BIP",
		DOT11_CIPHER_ALGORITHM.BIP_GMAC_128 => "BIP-GMAC-128",
		DOT11_CIPHER_ALGORITHM.BIP_GMAC_256 => "BIP-GMAC-256",
		DOT11_CIPHER_ALGORITHM.BIP_CMAC_256 => "BIP-CMAC-256",
		_ => algorithm.ToString()
	};
}
