# Beszel Agent Edge for ESP32-C6 - Arduino

Beszel Agent port for Arduino-compatible sketch for Seeed Studio XIAO ESP32-C6.

## Hardware

- **Board**: Seeed Studio XIAO ESP32-C6
- **Flash**: 4MB+ SPI Flash
- **RAM**: 320KB SRAM
- **Connectivity**: WiFi 6 (802.11ax) | Bluetooth

## Installation

### 1. Install ESP32 Board Support

1. Open Arduino IDE
2. Go to **File > Preferences**
3. Add to "Additional Boards Manager URLs":
   ```
   https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json
   ```
4. Go to **Tools > Board > Boards Manager**
5. Search for "esp32" and install "ESP32 by Espressif Systems"

### 2. Install Dependencies

In Arduino IDE, go to **Sketch > Include Library > Manage Libraries** and install:
- **WebSockets** by Markus Sattler
- **Preferences** (built into ESP32 core)

### 3. Select Board

1. Go to **Tools > Board > ESP32 > XIAO_ESP32C6**
2. Select the correct Port

### 4. Upload

1. Open `beszel_agent.ino`
2. Click Upload

## Configuration

After upload, open **Tools > Serial Monitor** (115200 baud).

### Configure via Serial

Send commands:
```
SET,hub_url=https://your-hub.com,token=your-token,ssid=YourWiFi,pass=YourPassword,name=MyESP32
```

### Commands

| Command | Description |
|---------|-------------|
| `SET,...` | Set configuration (hub_url, token, ssid, pass, name) |
| `STATUS` | Show connection status |
| `RESET` | Clear all configuration |
| `RECONNECT` | Force WebSocket reconnection |
| `HELP` | Show available commands |

### Web UI (AP Mode)

When no WiFi is configured, the device creates an AP named `Beszel-Setup` (coming soon).

## Features

- Connects to Beszel Hub via secure WebSocket (WSS)
- Reports CPU, Memory, Uptime metrics
- Handles CheckFingerprint authentication
- Automatic reconnection
- Serial configuration interface

## Protocol

The agent communicates with Beszel Hub using CBOR-encoded messages over WebSocket.

## Pinout (XIAO ESP32-C6)

```
GPIO0  - User LED (built-in)
GPIO1  - TX (debug)
GPIO2  - RX (debug)
GPIO20 - USB D+
GPIO19 - USB D-
```

## Resources

- [Beszel Hub](https://github.com/henry.eval/beszel)
- [XIAO ESP32-C6 Wiki](https://wiki.seeedstudio.com/XIAO_ESP32C6_Getting_Started)
