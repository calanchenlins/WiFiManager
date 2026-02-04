# WiFiManager

[中文](#简介) | [English](#introduction)

![.NET](https://img.shields.io/badge/.NET-8.0-512BD4) ![Platform](https://img.shields.io/badge/Platform-Windows-0078D6) ![License](https://img.shields.io/badge/License-MIT-green)

---

## Introduction

**WiFiManager** is a lightweight command-line tool for Windows designed to manage Wi-Fi connections. It provides robust monitoring and auto-reconnection capabilities, making it ideal for maintaining stable connections on unattended devices or servers. It also features a powerful scanner that can list detailed BSSID information.

Built with .NET 8 and utilizes the Native Windows WLAN API.

### Key Features

*   **Connection Monitoring (Two Modes)**:
    *   **Gateway Mode**: Continuously pings a gateway and automatically reconnects if the connection drops.
    *   **BSSID Mode**: Monitors the current connection and reconnects if disconnected or connected to a different SSID/BSSID.
*   **BSSID Locking**: Can target a specific Access Point (BSSID), useful for troubleshooting roaming issues or connecting to a specific node in a mesh network.
*   **Detailed Scanning**:
    *   **Network Mode**: Summarizes available networks by SSID.
    *   **BSSID Mode**: Lists every visible AP with details like Frequency, RSSI, Link Quality, PHY type, and Band (2.4GHz/5GHz/6GHz).
*   **Single File**: Compiled as a self-contained, single-file executable for easy deployment.

### System Requirements

- Windows 10 version 1809 (build 17763) or later
- Administrator privileges may be required for some operations
- A Wi-Fi adapter with proper drivers installed

### Quick Reference

| Command | Description |
|---------|-------------|
| `WiFiManager scan` | Scan networks (summary) |
| `WiFiManager scan -m bssid` | Scan networks (detailed) |
| `WiFiManager connect -s "WiFi" -g 192.168.1.1` | Gateway mode |
| `WiFiManager connect -s "WiFi" -b "AA:BB:CC:DD:EE:FF"` | BSSID mode |
| `WiFiManager show interface` | List Wi-Fi interfaces |

## Usage

### 1. Connect & Monitor

Monitor connectivity and reconnect to a specific WiFi network when needed. **You must choose one mode: Gateway or BSSID.**

```powershell
# Gateway Mode: Ping gateway to check connectivity
WiFiManager.exe connect --ssid "MyWiFi" --gateway 192.168.1.1

# BSSID Mode: Monitor connection to a specific BSSID
WiFiManager.exe connect --ssid "MyWiFi" --bssid "12:34:56:78:90:AB"

# Specify interface by name or GUID
WiFiManager.exe connect --ssid "MyWiFi" --gateway 192.168.1.1 --interface "Intel(R) Wi-Fi"
```

> Note: This tool uses existing Wi-Fi profiles saved in Windows. It triggers connection to profiles matching the SSID.

**Options:**

*   `-s, --ssid`: (Required) The SSID of the Wi-Fi network.
*   `-b, --bssid`: The specific BSSID (MAC address) to connect to. **Cannot be used with `--gateway`.**
*   `-g, --gateway`: The IP address of the gateway to ping for connectivity checks. **Cannot be used with `--bssid`.**
*   `-i, --interval`: (Optional) Check interval in seconds (default: 5).
*   `-c, --config`: (Optional) Path to a JSON configuration file.
*   `-n, --interface`: (Optional) Target Wi-Fi interface (GUID or name substring). Defaults to the first interface.

**Mode Behavior:**

| Mode | Trigger Reconnection When |
|------|---------------------------|
| Gateway | Gateway ping fails |
| BSSID | Not connected, or connected to different SSID/BSSID |

### 2. Scan Networks

List available Wi-Fi networks.

```powershell
# Summary view (default)
WiFiManager.exe scan

# Detailed BSSID view
WiFiManager.exe scan --mode bssid

# Scan using a specific interface
WiFiManager.exe scan --mode bssid --interface "Intel(R) Wi-Fi"
```

**Options:**

*   `-m, --mode`: Scan mode. `network` (default) or `bssid`.
*   `-n, --interface`: (Optional) Target Wi-Fi interface (GUID or name substring). Defaults to the first interface.

### 3. Show Interfaces

List all Wi-Fi interfaces and their states:

```powershell
WiFiManager.exe show interface
```

### Configuration File

You can use a JSON file instead of command-line arguments.

**Gateway Mode** (`config.json`):
```json
{
  "SSID": "MyWiFi",
  "Gateway": "192.168.1.1",
  "Interval": 10
}
```

**BSSID Mode** (`config.json`):
```json
{
  "SSID": "MyWiFi",
  "BSSID": "aa:bb:cc:dd:ee:ff",
  "Interval": 10
}
```

> Note: `Gateway` and `BSSID` are mutually exclusive. Specify only one.

Run with config:
```powershell
WiFiManager.exe connect --config ./config.json
```

## Screenshots

> scan

![Screenshot](docs/images/screenshot1.png)

> connect

![Screenshot](docs/images/screenshot2.png)

## Build

Requirements: .NET 8 SDK

```powershell
dotnet publish -c Release
```

The executable will be in `bin/Release/net8.0/win-x64/publish/`.

## Troubleshooting

| Issue | Cause | Solution |
|-------|-------|----------|
| `Connection attempt failed` | Wi-Fi profile not saved in Windows | Manually connect to the network once via Windows Settings to create the profile |
| `No Wi-Fi interfaces found` | No wireless adapter detected or driver issue | Check Device Manager, ensure Wi-Fi adapter is enabled and drivers are installed |
| `Access is denied` (Error 5) | Insufficient permissions | Run as Administrator, or ensure the user has rights to manage Wi-Fi |
| `The network is not available` | Target SSID not in range or hidden | Move closer to AP, or ensure SSID is broadcasting |
| Connection drops repeatedly | Weak signal or interference | Use `scan --mode bssid` to check signal strength; consider BSSID lock to prevent roaming |
| Service fails to connect | SYSTEM account cannot access user Wi-Fi profiles | Export the profile as "All Users" using `netsh wlan export profile folder=. key=clear` and re-import |

**Useful diagnostic commands:**

```powershell
# List saved Wi-Fi profiles
netsh wlan show profiles

# Show detailed profile info (including password if admin)
netsh wlan show profile name="MyWiFi" key=clear

# Check current connection status
netsh wlan show interfaces
```

## Exit Codes

| Code | Meaning |
|------|---------|  
| 0 | Success or graceful shutdown (Ctrl+C) |
| 1 | Configuration error or runtime failure |

## License

Released under the [MIT License](LICENSE).

## Run as a Windows Service (WinSW)

Use [WinSW](https://github.com/winsw/winsw) to run WiFiManager in the background as a Windows service.

### 1. Prepare files

Put the following files in the same folder, e.g. `C:\WiFiManager\`:

* `WiFiManager.exe`
* `config.json` (optional config file for this tool)
* `winsw.xml` (WinSW config, example below)
* `winsw.exe` (download the WinSW binary and rename it to `WiFiManager.exe` **or** keep `winsw.exe` and use `winsw.xml`)

> Note: The WinSW wrapper executable name should match the XML name (e.g., `winsw.exe` + `winsw.xml`). 

### 2. WinSW configuration

Example `winsw.xml`:

```xml
<service>
  <id>WiFiManager</id>
  <name>WiFiManager</name>
  <description>WiFiManager background service</description>
  <executable>WiFiManager.exe</executable>
  <arguments>connect -c config.json</arguments>
  <log mode="roll-by-size">
    <sizeThreshold>10240</sizeThreshold>
    <keepFiles>8</keepFiles>
  </log>
  <onfailure action="restart" delay="10 sec"/>
</service>
```

### 3. Install and start service

Run in an elevated PowerShell:

```powershell
cd C:\WiFiManager\
.\winsw.exe install
.\winsw.exe start
```

### 4. Stop and uninstall

```powershell
.\winsw.exe stop
.\winsw.exe uninstall
```

Logs are stored in the same directory by default (rolling logs).

---

## 简介

**WiFiManager** 是一个轻量级的 Windows 命令行工具，专为管理 Wi-Fi 连接设计。它提供了强大的连接监控和自动断线重连功能，非常适合在无人值守的设备或服务器上维护稳定的网络连接。此外，它还包含一个强大的扫描器，可以列出详细的 BSSID 信息。

基于 .NET 8 构建，直接调用原生 Windows WLAN API。

### 主要功能

*   **连接监控（两种模式）**：
    *   **Gateway 模式**：持续 Ping 指定网关，一旦检测到掉线即自动尝试重连。
    *   **BSSID 模式**：监控当前连接状态，若未连接或连接到不同的 SSID/BSSID 则自动重连。
*   **BSSID 锁定**：可以指定连接到特定的接入点（BSSID），这在排查漫游问题或连接到 Mesh 网络中的特定节点时非常有用。
*   **详细扫描**：
    *   **网络模式**：按 SSID 汇总可用网络。
    *   **BSSID 模式**：列出每个可见的 AP 详细信息，包括频率、RSSI、链路质量、PHY 类型和频段（2.4GHz/5GHz/6GHz）。
*   **单文件**：编译为自包含的单文件可执行程序，无需安装运行时，便于部署。

### 系统要求

- Windows 10 版本 1809（内部版本 17763）或更高版本
- 部分操作可能需要管理员权限
- 已安装正确驱动程序的 Wi-Fi 适配器

### 命令速查

| 命令 | 说明 |
|------|------|
| `WiFiManager scan` | 扫描网络（摘要） |
| `WiFiManager scan -m bssid` | 扫描网络（详细） |
| `WiFiManager connect -s "WiFi" -g 192.168.1.1` | Gateway 模式 |
| `WiFiManager connect -s "WiFi" -b "AA:BB:CC:DD:EE:FF"` | BSSID 模式 |
| `WiFiManager show interface` | 显示网卡列表 |

## 使用说明

### 1. 连接与监控

监控网络连通性，并在需要时重连到指定的 Wi-Fi。**必须选择一种模式：Gateway 或 BSSID。**

```powershell
# Gateway 模式：通过 Ping 网关检测连通性
WiFiManager.exe connect --ssid "MyWiFi" --gateway 192.168.1.1

# BSSID 模式：监控到特定 BSSID 的连接
WiFiManager.exe connect --ssid "MyWiFi" --bssid "12:34:56:78:90:AB"

# 指定网卡接口（名称或 GUID）
WiFiManager.exe connect --ssid "MyWiFi" --gateway 192.168.1.1 --interface "Intel(R) Wi-Fi"
```

> 注意：该工具主要利用 Windows 中已保存的 Wi-Fi 配置文件进行连接。

**参数：**

*   `-s, --ssid`: （必填）Wi-Fi 名称 (SSID)。
*   `-b, --bssid`: 要连接的特定 BSSID (MAC 地址)。**不能与 `--gateway` 同时使用。**
*   `-g, --gateway`: 用于检测连通性的网关 IP 地址。**不能与 `--bssid` 同时使用。**
*   `-i, --interval`: (选填) 检测间隔，单位秒 (默认: 5)。
*   `-c, --config`: (选填) JSON 配置文件路径。
*   `-n, --interface`: (选填) 目标 Wi-Fi 网卡（GUID 或名称关键字）。默认使用首个无线网卡。

**模式行为：**

| 模式 | 触发重连条件 |
|------|-------------|
| Gateway | 网关 Ping 失败 |
| BSSID | 未连接，或连接到不同的 SSID/BSSID |

### 2. 扫描网络

列出当前环境可用的 Wi-Fi 网络。

```powershell
# 摘要视图 (默认)
WiFiManager.exe scan

# 详细 BSSID 视图
WiFiManager.exe scan --mode bssid

# 使用指定网卡进行扫描
WiFiManager.exe scan --mode bssid --interface "Intel(R) Wi-Fi"
```

**参数：**

*   `-m, --mode`: 扫描模式。`network` (默认，按网络汇总) 或 `bssid` (列出所有物理接入点)。
*   `-n, --interface`: (选填) 目标 Wi-Fi 网卡（GUID 或名称关键字）。默认使用首个无线网卡。

### 3. 显示网卡信息

列出所有无线网卡及其当前状态：

```powershell
WiFiManager.exe show interface
```

### 配置文件

你可以使用 JSON 文件来替代命令行参数。

**Gateway 模式** (`config.json`):
```json
{
  "SSID": "MyWiFi",
  "Gateway": "192.168.1.1",
  "Interval": 10
}
```

**BSSID 模式** (`config.json`):
```json
{
  "SSID": "MyWiFi",
  "BSSID": "aa:bb:cc:dd:ee:ff",
  "Interval": 10
}
```

> 注意：`Gateway` 和 `BSSID` 互斥，只能指定其中一个。

使用配置运行：
```powershell
WiFiManager.exe connect --config ./config.json
```

## 效果截图

> scan

![Screenshot](docs/images/screenshot1.png)

> connect

![Screenshot](docs/images/screenshot2.png)

## 构建

环境要求：.NET 8 SDK

```powershell
dotnet publish -c Release
```

生成的可执行文件位于 `bin/Release/net8.0/win-x64/publish/`。

## 故障排除

| 问题 | 原因 | 解决方案 |
|------|------|----------|
| `Connection attempt failed` | Windows 中未保存该 Wi-Fi 配置文件 | 先通过 Windows 设置手动连接一次该网络以创建配置文件 |
| `No Wi-Fi interfaces found` | 未检测到无线网卡或驱动问题 | 检查设备管理器，确保 Wi-Fi 适配器已启用且驱动已安装 |
| `Access is denied` (错误 5) | 权限不足 | 以管理员身份运行，或确保用户具有管理 Wi-Fi 的权限 |
| `The network is not available` | 目标 SSID 不在范围内或为隐藏网络 | 靠近接入点，或确保 SSID 正在广播 |
| 连接反复断开 | 信号弱或干扰 | 使用 `scan --mode bssid` 检查信号强度；考虑使用 BSSID 锁定防止漫游 |
| 服务无法连接 | SYSTEM 账户无法访问用户的 Wi-Fi 配置文件 | 使用 `netsh wlan export profile folder=. key=clear` 导出配置文件为"所有用户"，然后重新导入 |

**常用诊断命令：**

```powershell
# 列出已保存的 Wi-Fi 配置文件
netsh wlan show profiles

# 显示详细配置信息（管理员可查看密码）
netsh wlan show profile name="MyWiFi" key=clear

# 检查当前连接状态
netsh wlan show interfaces
```

## 退出码

| 代码 | 含义 |
|------|------|
| 0 | 成功或正常退出（Ctrl+C） |
| 1 | 配置错误或运行时错误 |

## 许可证

基于 [MIT License](LICENSE) 发布。

## 后台服务（WinSW）

使用 [WinSW](https://github.com/winsw/winsw) 将 WiFiManager 作为 Windows 服务后台守护运行。

### 1. 准备文件

将以下文件放到同一目录，例如 `C:\WiFiManager\`：

* `WiFiManager.exe`
* `config.json`（可选，工具配置文件）
* `winsw.exe`
* `winsw.xml`（WinSW 配置，示例见下）

> 注意：WinSW 包装程序的可执行文件名需要与 XML 名称一致（如 `winsw.exe` + `winsw.xml`）。

### 2. WinSW 配置

`winsw.xml` 示例：

```xml
<service>
  <id>WiFiManager</id>
  <name>WiFiManager</name>
  <description>WiFiManager background service</description>
  <executable>WiFiManager.exe</executable>
  <arguments>connect -c config.json</arguments>
  <log mode="roll-by-size">
    <sizeThreshold>10240</sizeThreshold>
    <keepFiles>8</keepFiles>
  </log>
  <onfailure action="restart" delay="10 sec"/>
</service>
```

### 3. 安装并启动服务

使用管理员 PowerShell：

```powershell
cd C:\WiFiManager\
.\winsw.exe install
.\winsw.exe start
```

### 4. 停止并卸载

```powershell
.\winsw.exe stop
.\winsw.exe uninstall
```

默认日志保存在同目录（滚动日志）。
