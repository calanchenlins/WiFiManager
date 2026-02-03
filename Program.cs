using System.CommandLine;
using System.CommandLine.Parsing;
using System.ComponentModel;
using System.Linq;
using System.Net.NetworkInformation;
using System.Text.Json;
using System.Text.Json.Serialization;

internal class Program
{
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

		showInterfaceCommand.SetAction((_, cancellationToken) => RunShowInterfaceAsync(cancellationToken));
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
			Console.WriteLine($"[{DateTime.Now:yyyyMMdd HH:mm:ss}] Configuration error: {ex.Message}");
			return 1;
		}

		using var wlan = new WlanClient();
		if (!TryResolveInterface(wlan, options.Interface, out var selectedInterface, out var error))
		{
			Console.WriteLine($"[{DateTime.Now:yyyyMMdd HH:mm:ss}] {error}");
			return 1;
		}

		Console.WriteLine($"[{DateTime.Now:yyyyMMdd HH:mm:ss}] Using interface: {selectedInterface.strInterfaceDescription} (State: {selectedInterface.isState}, GUID: {selectedInterface.InterfaceGuid}).");
		Console.WriteLine($"[{DateTime.Now:yyyyMMdd HH:mm:ss}] Monitoring gateway {config.Gateway} every {config.Interval}s for SSID '{config.SSID}' (BSSID: {config.BSSID ?? "any"}). Press Ctrl+C to exit.");

		DateTime? successStart = null;
		DateTime? lastSuccess = null;

		while (!cancellationToken.IsCancellationRequested)
		{
			var reachable = await NetworkHelper.PingAsync(config.Gateway, TimeSpan.FromSeconds(2), cancellationToken).ConfigureAwait(false);
			if (reachable)
			{
				var now = DateTime.Now;
				successStart ??= now;
				lastSuccess = now;
			}
			else
			{
				if (successStart.HasValue && lastSuccess.HasValue)
				{
					Console.WriteLine($"[{DateTime.Now:yyyyMMdd HH:mm:ss}] Gateway connectivity was healthy from {successStart:yyyyMMdd HH:mm:ss} to {lastSuccess:yyyyMMdd HH:mm:ss}.");
					successStart = null;
					lastSuccess = null;
				}

				Console.WriteLine($"[{DateTime.Now:yyyyMMdd HH:mm:ss}] Gateway unreachable. Reconnecting...");
				try
				{
					await wlan.ConnectAsync(selectedInterface.InterfaceGuid, config.SSID, config.BSSID, cancellationToken).ConfigureAwait(false);
				}
				catch (Win32Exception ex)
				{
					Console.WriteLine($"[{DateTime.Now:yyyyMMdd HH:mm:ss}] Reconnect failed with Win32 error {ex.NativeErrorCode}: {ex.Message}");
				}
				catch (Exception ex)
				{
					Console.WriteLine($"[{DateTime.Now:yyyyMMdd HH:mm:ss}] Reconnect failed: {ex.Message}\r\n{ex.StackTrace}");
				}
			}

			await Task.Delay(TimeSpan.FromSeconds(config.Interval), cancellationToken).ConfigureAwait(false);
		}

		return 0;
	}

	private static async Task<int> RunScanAsync(ScanOptions options, CancellationToken cancellationToken)
	{
		using var wlan = new WlanClient();
		if (!TryResolveInterface(wlan, options.Interface, out var selectedInterface, out var error))
		{
			Console.WriteLine($"[{DateTime.Now:yyyyMMdd HH:mm:ss}] {error}");
			return 1;
		}

		Console.WriteLine($"[{DateTime.Now:yyyyMMdd HH:mm:ss}] Using interface: {selectedInterface.strInterfaceDescription} (State: {selectedInterface.isState}, GUID: {selectedInterface.InterfaceGuid}).");
		Console.WriteLine(options.Mode == ScanMode.Bssid ? $"[{DateTime.Now:yyyyMMdd HH:mm:ss}] Scanning for BSS entries..." : $"[{DateTime.Now:yyyyMMdd HH:mm:ss}] Scanning for available Wi-Fi networks...");

		try
		{
			if (options.Mode == ScanMode.Bssid)
			{
				var bssList = await wlan.ScanBssAsync(selectedInterface.InterfaceGuid, cancellationToken).ConfigureAwait(false);
				if (bssList.Count == 0)
				{
					Console.WriteLine($"[{DateTime.Now:yyyyMMdd HH:mm:ss}] No BSS entries found.");
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
					Console.WriteLine($"[{DateTime.Now:yyyyMMdd HH:mm:ss}] No networks found.");
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
							BssCount = (uint)totalBssids
						};
					})
					.OrderByDescending(n => n.SignalQuality)
					.ToList();

				for (var i = 0; i < grouped.Count; i++)
				{
					var n = grouped[i];
					Console.WriteLine($"{i + 1}. SSID: {n.SSID}, Signal: {n.SignalQuality}%, Security: {(n.SecurityEnabled ? "On" : "Off")}, BSSIDs: {n.BssCount}, Type: {n.BssType}");
				}
			}
		}
		catch (Win32Exception ex)
		{
			Console.WriteLine($"[{DateTime.Now:yyyyMMdd HH:mm:ss}] Scan failed with Win32 error {ex.NativeErrorCode}: {ex.Message}");
			return 1;
		}
		catch (Exception ex)
		{
			Console.WriteLine($"[{DateTime.Now:yyyyMMdd HH:mm:ss}] Scan failed: {ex.Message}");
			return 1;
		}

		return 0;
	}

	private static Task<int> RunShowInterfaceAsync(CancellationToken cancellationToken)
	{
		using var wlan = new WlanClient();
		var interfaces = wlan.GetInterfaces();
		if (interfaces.Count == 0)
		{
			Console.WriteLine($"[{DateTime.Now:yyyyMMdd HH:mm:ss}] No Wi-Fi interfaces found.");
			return Task.FromResult(1);
		}

		for (var i = 0; i < interfaces.Count; i++)
		{
			var iface = interfaces[i];
			Console.WriteLine($"{i + 1}. {iface.strInterfaceDescription} (State: {iface.isState}, GUID: {iface.InterfaceGuid})");
		}

		return Task.FromResult(0);
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
			.ToList();

		if (matches.Count == 1)
		{
			selected = matches[0];
			error = null;
			return true;
		}

		selected = default;
		if (matches.Count > 1)
		{
			error = $"Multiple interfaces matched '{selector}'. Please specify the full GUID or a more specific name.";
		}
		else
		{
			error = $"No interface matched '{selector}'.";
		}

		return false;
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

internal sealed record AppConfig(string SSID, string? BSSID, string Gateway, int Interval)
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

		if (string.IsNullOrWhiteSpace(gateway))
		{
			throw new ArgumentException("Gateway is required.");
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
	public static async Task<bool> PingAsync(string host, TimeSpan timeout, CancellationToken cancellationToken)
	{
		using var ping = new Ping();
		try
		{
			// WaitAsync(timeout, cancellationToken)
			var reply = await ping.SendPingAsync(host, (int)timeout.TotalMilliseconds).ConfigureAwait(false);
			return reply.Status == IPStatus.Success;
		}
		catch (PingException)
		{
			return false;
		}
		catch (TimeoutException)
		{
			return false;
		}
	}
}

internal static class ScanHelpers
{
	public static string? GetBand(uint frequencyKhz)
	{
		if (frequencyKhz == 0)
		{
			return null;
		}

		var mhz = frequencyKhz / 1000.0;
		if (mhz >= 2400 && mhz <= 2500)
		{
			return "2.4 GHz";
		}

		if (mhz >= 4900 && mhz <= 5925)
		{
			return "5 GHz";
		}

		if (mhz >= 5925 && mhz <= 7125)
		{
			return "6 GHz";
		}

		if (mhz >= 57000 && mhz <= 71000)
		{
			return "60 GHz";
		}

		return null;
	}
}
