/*
 * Beszel Agent Edge for ESP32-C6
 * =========================
 * A lightweight monitoring agent that connects to Beszel Hub via WebSocket
 * and reports real-time system metrics from ESP32-C6 microcontrollers.
 *
 * PROTOCOL: PUSH Mode (Agent initiates, no TCP server needed)
 * AUTH: Universal Token (X-Token header)
 * ENCODING: CBOR with keyAsInt (integer keys per Beszel spec)
 *
 * HARDWARE: Seeed Studio XIAO ESP32-C6 or similar
 * PLATFORM: Arduino framework
 *
 * CBOR KEY MAPPING (from Beszel Hub source):
 *
 * CombinedData = {0: Stats, 1: Info}
 *
 * Stats (key 0):
 *   0 = Cpu (float64)           - CPU usage (0% for MCU)
 *   2 = MemTotal (float64)      - Total RAM in MB
 *   3 = MemUsed (float64)       - Used RAM in MB
 *   4 = MemPct (float64)        - Memory usage percentage
 *   9 = DiskTotal (float64)     - Total flash storage in MB
 *   10 = DiskUsed (float64)      - Used flash storage in MB
 *   11 = DiskPct (float64)       - Storage usage percentage
 *   20 = Temperature (map)       - Sensor readings map
 *         "ESP32_Core" = Internal temperature (float64)
 *         "WiFi_RSSI"  = WiFi signal strength (float64)
 *
 * Info (key 1):
 *   5  = Uptime (uint64)        - Seconds since boot
 *   6  = Cpu (float64)          - CPU usage
 *   7  = MemPct (float64)       - Memory usage percentage
 *   10 = AgentVersion (string)  - Agent version string
 *   13 = Temp (float64)         - Temperature for dashboard
 *   18 = Bandwidth (uint64)     - Network bandwidth (0 for MCU)
 *   20 = ConnectionType (int)    - 2 = WebSocket
 *
 * PROTOCOL FLOW:
 * 1. Connect WebSocket to hub_url/api/beszel/agent-connect
 * 2. Hub sends CheckFingerprint (action=1) with req_id + 64-byte signature
 * 3. Agent responds with FingerprintResponse wrapped in AgentResponse
 * 4. Hub sends GetData (action=0) periodically
 * 5. Agent responds with CombinedData wrapped in AgentResponse
 */

#include <Arduino.h>
#include <WiFi.h>
#include <WebSocketsClient.h>
#include <Preferences.h>
#include <LittleFS.h>

#define VERSION "1.0.0"
#define RECONNECT_MS 30000
// #define METRICS_INTERVAL_MS 30000
#define LED_PIN 15
#define LED_BLINK_MS 100

Preferences prefs;
WebSocketsClient ws;

bool connected = false;
unsigned long last_connect = 0;
unsigned long last_metrics = 0;
char ser_buf[256];
uint8_t ser_len = 0;
bool led_blink = true;

String hub_url, token, wifi_ssid, wifi_pass, device_name;
bool configured = false;

/*
 * Generate unique fingerprint from MAC address.
 * Format: "esp32-xxxxxxxxxxxx" (lowercase hex)
 */
static void generate_fingerprint(char *buf, size_t len) {
    uint8_t mac[6];
    WiFi.macAddress(mac);
    snprintf(buf, len, "esp32-%02x%02x%02x%02x%02x%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/*
 * Extract request ID from CBOR payload.
 * Skips 64-byte signature block (0x58 0x40) to avoid misidentification.
 * Supports dynamic length encoding (1/8/16/32-bit integers).
 */
static uint32_t get_request_id(const uint8_t *cbor, size_t len) {
    for (size_t i = 1; i < len - 1; i++) {
        if (cbor[i] == 0x58 && i + 1 < len && cbor[i+1] == 0x40) {
            i += 65;
            continue;
        }
        if (cbor[i] == 0x02) {
            uint8_t tag = cbor[i+1];
            if (tag <= 0x17) return tag;
            if (tag == 0x18 && i + 2 < len) return cbor[i+2];
            if (tag == 0x19 && i + 3 < len) return (cbor[i+2]<<8)|cbor[i+3];
            if (tag == 0x1A && i + 5 < len) {
                return ((uint32_t)cbor[i+2]<<24)|((uint32_t)cbor[i+3]<<16)|
                       ((uint32_t)cbor[i+4]<<8)|cbor[i+5];
            }
        }
    }
    return 0;
}

/*
 * Get action type from CBOR request.
 * Returns: 1 = CheckFingerprint, 0 = GetData, -1 = Unknown
 */
static int get_action(const uint8_t *cbor, size_t len) {
    if (len < 4 || cbor[0] != 0xA3) return -1;
    if (cbor[1] == 0x00) return cbor[2];
    return -1;
}

/*
 * Extract 64-byte signature from CheckFingerprint message.
 * Signature is at offset 8 in the CBOR payload.
 */
static int extract_signature(const uint8_t *cbor, size_t len, uint8_t *sig_out) {
    if (len < 10 || cbor[0] != 0xA3) return -1;
    if (cbor[1] != 0x00 || cbor[2] != 0x01) return -1;
    if (cbor[3] != 0x01 || cbor[4] != 0xA2) return -1;
    if (cbor[5] != 0x00 || cbor[6] != 0x58 || cbor[7] != 0x40) return -1;
    if (len < 8 + 64) return -1;
    memcpy(sig_out, cbor + 8, 64);
    return 0;
}

/* ============================================================================
 * CBOR ENCODING HELPERS
 * Beszel Hub uses fxamacker/cbor with strict canonical encoding.
 * All integers must use minimum byte representation.
 * ============================================================================ */

/*
 * Encode unsigned integer in canonical CBOR format.
 * Uses minimum bytes: 1-byte for 0-23, 2-byte for 24-255, etc.
 */
static size_t enc_uint(uint8_t *b, size_t o, uint64_t v) {
    size_t start = o;
    if (v <= 23) { b[o++] = v; }
    else if (v <= 0xFF) { b[o++] = 0x18; b[o++] = v; }
    else if (v <= 0xFFFF) { b[o++] = 0x19; b[o++] = v >> 8; b[o++] = v & 0xFF; }
    else if (v <= 0xFFFFFFFF) {
        b[o++] = 0x1A;
        b[o++] = v >> 24;
        b[o++] = (v >> 16) & 0xFF;
        b[o++] = (v >> 8) & 0xFF;
        b[o++] = v & 0xFF;
    } else {
        b[o++] = 0x1B;
        for (int i = 7; i >= 0; i--) b[o++] = (v >> (i * 8)) & 0xFF;
    }
    return o - start;
}

/*
 * Encode 64-bit float (IEEE 754) in CBOR format.
 * Tag 0xFB + 8 bytes (big-endian).
 */
static size_t enc_f64(uint8_t *b, size_t o, double v) {
    uint64_t bits;
    memcpy(&bits, &v, 8);
    b[o++] = 0xFB;
    for (int i = 7; i >= 0; i--) {
        b[o++] = (bits >> (i * 8)) & 0xFF;
    }
    return 9;
}

/*
 * Encode text string in CBOR format.
 * Supports strings > 23 chars using 0x78 (1-byte length).
 */
static size_t enc_text(uint8_t *b, size_t o, const char *s) {
    size_t l = strlen(s);
    size_t start = o;
    if (l <= 23) {
        b[o++] = 0x60 | l;
    } else if (l <= 255) {
        b[o++] = 0x78;
        b[o++] = l & 0xFF;
    }
    memcpy(b + o, s, l);
    return (o + l) - start;
}

/* ============================================================================
 * CBOR STRUCTURE BUILDERS
 * These functions build the exact CBOR structures expected by Beszel Hub.
 * Key ordering and types must match Beszel specification exactly.
 * ============================================================================ */

/*
 * Build Info CBOR structure (7 keys).
 * Keys: Uptime(5), Cpu(6), MemPct(7), Temp(13), Bandwidth(18), ConnType(20), Version(10)
 */
static size_t enc_info(uint8_t *buf, uint64_t uptime, double cpu, double mem_pct, double temp) {
    size_t o = 0;
    buf[o++] = 0xA7;
    buf[o++] = 5; o += enc_uint(buf, o, uptime);
    buf[o++] = 6; o += enc_f64(buf, o, cpu);
    buf[o++] = 7; o += enc_f64(buf, o, mem_pct);
    buf[o++] = 13; o += enc_f64(buf, o, temp);
    buf[o++] = 18; o += enc_uint(buf, o, 0);
    buf[o++] = 20; buf[o++] = 2;
    buf[o++] = 10; o += enc_text(buf, o, VERSION);
    return o;
}

/*
 * Build Stats CBOR structure (8 keys).
 * Keys: Cpu(0), MemTotal(2), MemUsed(3), MemPct(4), DiskTotal(9),
 *       DiskUsed(10), DiskPct(11), Temperature(20)
 */
static size_t enc_stats(uint8_t *buf, double cpu, double mem_total, double mem_used, double mem_pct,
                        double disk_total, double disk_used, double disk_pct,
                        double temp, double rssi) {
    size_t o = 0;
    buf[o++] = 0xA8;
    buf[o++] = 0; o += enc_f64(buf, o, cpu);
    buf[o++] = 2; o += enc_f64(buf, o, mem_total);
    buf[o++] = 3; o += enc_f64(buf, o, mem_used);
    buf[o++] = 4; o += enc_f64(buf, o, mem_pct);
    buf[o++] = 9; o += enc_f64(buf, o, disk_total);
    buf[o++] = 10; o += enc_f64(buf, o, disk_used);
    buf[o++] = 11; o += enc_f64(buf, o, disk_pct);

    buf[o++] = 20;
    buf[o++] = 0xA2;
    o += enc_text(buf, o, "ESP32_Core"); o += enc_f64(buf, o, temp);
    o += enc_text(buf, o, "WiFi_RSSI"); o += enc_f64(buf, o, rssi);

    return o;
}

/*
 * Build CombinedData wrapper: {0: Stats, 1: Info}
 */
static size_t enc_combined_data(uint8_t *buf,
                                double cpu, double mem_total, double mem_used, double mem_pct,
                                double disk_total, double disk_used, double disk_pct,
                                double temp, double rssi,
                                uint64_t uptime) {
    size_t o = 0;
    buf[o++] = 0xA2;
    buf[o++] = 0;
    o += enc_stats(buf + o, cpu, mem_total, mem_used, mem_pct, disk_total, disk_used, disk_pct, temp, rssi);
    buf[o++] = 1;
    o += enc_info(buf + o, uptime, cpu, mem_pct, temp);
    return o;
}

/*
 * Build FingerprintResponse wrapped in AgentResponse.
 * Structure: {0: req_id, 2: {0: fingerprint, 1: hostname, 2: port, 3: name}}
 */
static size_t enc_fp_response(uint8_t *buf, uint32_t req_id,
                               const char *fingerprint, const char *hostname,
                               const char *port, const char *name) {
    size_t o = 0;
    buf[o++] = 0xA2;
    buf[o++] = 0;
    o += enc_uint(buf, o, req_id);
    buf[o++] = 2;
    buf[o++] = 0xA4;
    buf[o++] = 0; o += enc_text(buf, o, fingerprint);
    buf[o++] = 1; o += enc_text(buf, o, hostname);
    buf[o++] = 2; o += enc_text(buf, o, port);
    buf[o++] = 3; o += enc_text(buf, o, name);
    return o;
}

/* ============================================================================
 * METRICS COLLECTION
 * Collects real-time data from ESP32-C6 hardware sensors and system state.
 * ============================================================================ */

/*
 * Blink LED 3 times to indicate data transmission.
 * LED is active-LOW on XIAO ESP32-C6 (ON=LOW, OFF=HIGH).
 */
static void blink_led() {
    if (!led_blink) return;
    for (int i = 0; i < 3; i++) {
        digitalWrite(LED_PIN, LOW);
        delay(LED_BLINK_MS);
        digitalWrite(LED_PIN, HIGH);
        delay(LED_BLINK_MS);
    }
}

/*
 * Collect MCU metrics and send to Beszel Hub via WebSocket.
 * Metrics: CPU (0%), RAM (Heap), Flash (LittleFS), Temperature, WiFi RSSI
 */
static void send_metrics(uint32_t req_id) {
    double cpu = 0.0;

    double mem_total = ESP.getHeapSize() / (1024.0*1024.0);
    double mem_used = (ESP.getHeapSize() - ESP.getFreeHeap()) / (1024.0*1024.0);
    double mem_pct = (ESP.getHeapSize() > 0) ?
        (100.0 * (ESP.getHeapSize() - ESP.getFreeHeap()) / ESP.getHeapSize()) : 0;

    double disk_total = LittleFS.totalBytes() / (1024.0*1024.0);
    double disk_used = LittleFS.usedBytes() / (1024.0*1024.0);
    double disk_pct = (LittleFS.totalBytes() > 0) ?
        (100.0 * LittleFS.usedBytes() / LittleFS.totalBytes()) : 0;

    uint64_t uptime_secs = millis() / 1000;
    double temp = temperatureRead();
    double rssi = WiFi.RSSI();

    uint8_t data_buf[512];
    size_t data_len = enc_combined_data(data_buf, cpu, mem_total, mem_used, mem_pct,
                                        disk_total, disk_used, disk_pct, temp, rssi, uptime_secs);

    uint8_t resp[512];
    size_t o = 0;
    resp[o++] = 0xA2;
    resp[o++] = 0;
    o += enc_uint(resp, o, req_id);
    resp[o++] = 1;
    memcpy(resp + o, data_buf, data_len);
    o += data_len;

    Serial.printf("WS: Sending metrics (Mem: %.1f%%, Disk: %.1f%%, Temp: %.1fC, RSSI: %.0fdBm)\n",
                  mem_pct, disk_pct, temp, rssi);
    ws.sendBIN(resp, o);
    blink_led();
}

/* ============================================================================
 * WEBSOCKET HANDLING
 * Manages WebSocket connection lifecycle and message dispatching.
 * ============================================================================ */

void wsEvent(WStype_t type, uint8_t *data, size_t len) {
    switch (type) {
        case WStype_DISCONNECTED:
            connected = false;
            Serial.println("WS: Disconnected");
            break;

        case WStype_CONNECTED:
            connected = true;
            last_connect = millis();
            Serial.println("WS: Connected");
            break;

        case WStype_ERROR:
            Serial.println("WS: Error");
            break;

        case WStype_TEXT:
            Serial.printf("WS: Text: %.*s\n", len < 100 ? len : 100, data);
            break;

        case WStype_BIN: {
            if (len < 2) break;

            int action = get_action(data, len);
            uint32_t req_id = get_request_id(data, len);

            Serial.printf("WS: BIN action=%d req_id=%lu len=%d\n", action, req_id, len);

            if (action == 1) {
                Serial.println("WS: CheckFingerprint");
                uint8_t sig[64];
                extract_signature(data, len, sig);

                char fingerprint[32];
                char port[8];
                generate_fingerprint(fingerprint, sizeof(fingerprint));
                snprintf(port, sizeof(port), "%d", 0);

                uint8_t resp[128];
                size_t resp_len = enc_fp_response(resp, req_id, fingerprint,
                                                  WiFi.localIP().toString().c_str(),
                                                  port, device_name.c_str());
                ws.sendBIN(resp, resp_len);
            }
            else if (action == 0) {
                Serial.println("WS: GetData");
                send_metrics(req_id > 0 ? req_id : 1);
            }
            else {
                Serial.printf("WS: Unknown action: %d\n", action);
            }
            break;
        }

        default:
            break;
    }
}

/*
 * Establish WebSocket connection to Beszel Hub.
 * URL format: wss://hub.example.com/api/beszel/agent-connect
 */
void connectWs() {
    if (!hub_url.length() || !token.length()) {
        Serial.println("WS: No config");
        return;
    }

    String url = hub_url;
    url.replace("https://", "wss://");
    url.replace("http://", "ws://");
    if (!url.endsWith("/")) url += "/";
    url += "api/beszel/agent-connect";

    String host = url;
    host.replace("wss://", "");
    host.replace("ws://", "");
    int slash = host.indexOf('/');
    String path = "/";
    if (slash > 0) {
        path = host.substring(slash);
        host = host.substring(0, slash);
    }

    Serial.printf("WS: Connecting to %s%s\n", host.c_str(), path.c_str());

    ws.beginSSL(host.c_str(), 443, path.c_str());
    ws.onEvent(wsEvent);

    char headers[256];
    snprintf(headers, sizeof(headers), "X-Token: %s\r\nX-Beszel: %s",
             token.c_str(), VERSION);
    ws.setExtraHeaders(headers);

    ws.setReconnectInterval(5000);
}

/* ============================================================================
 * SERIAL COMMAND INTERFACE
 * CLI for configuration and debugging via USB serial.
 * ============================================================================ */

void setup() {
    Serial.begin(115200);
    delay(500);
    Serial.printf("\n=== Beszel Agent %s (CBOR Push) ===\n", VERSION);

    prefs.begin("beszel", false);
    hub_url = prefs.getString("hub_url", "");
    token = prefs.getString("token", "");
    wifi_ssid = prefs.getString("wifi_ssid", "");
    wifi_pass = prefs.getString("wifi_pass", "");
    device_name = prefs.getString("device_name", "ESP32-C6");
    configured = prefs.getBool("configured", false);
    led_blink = prefs.getBool("led_blink", true);
    prefs.end();

    if (!configured || hub_url.length() == 0) {
        Serial.println("Config needed. Send:");
        Serial.println("SET,hub_url=<url>,token=<tok>,ssid=<ss>,pass=<pw>,name=<nm>");
        return;
    }

    Serial.printf("WiFi: Connecting to %s\n", wifi_ssid.c_str());
    WiFi.mode(WIFI_STA);
    WiFi.begin(wifi_ssid.c_str(), wifi_pass.c_str());

    int i = 0;
    while (WiFi.status() != WL_CONNECTED && i++ < 20) delay(500);
    if (WiFi.status() != WL_CONNECTED) {
        Serial.println("WiFi: Failed");
        return;
    }

    Serial.printf("WiFi: Connected (%s, RSSI: %ddBm)\n",
                  WiFi.localIP().toString().c_str(), WiFi.RSSI());

    LittleFS.begin(true);
    Serial.printf("LittleFS: %u/%u bytes used\n", LittleFS.usedBytes(), LittleFS.totalBytes());

    pinMode(LED_PIN, OUTPUT);
    digitalWrite(LED_PIN, HIGH);
    Serial.printf("LED: Blink %s\n", led_blink ? "ON" : "OFF");

    connectWs();
}

void loop() {
    ws.loop();

    if (WiFi.status() == WL_CONNECTED && !ws.isConnected() &&
        millis() - last_connect > RECONNECT_MS) {
        Serial.println("WS: Reconnecting...");
        connectWs();
        last_connect = millis();
    }

    // if (connected && millis() - last_metrics > METRICS_INTERVAL_MS) {
    //     send_metrics(1);
    //     last_metrics = millis();
    // }

    while (Serial.available()) {
        char c = Serial.read();
        if (c == '\n' || c == '\r') {
            if (ser_len > 0) {
                ser_buf[ser_len] = 0;

                if (strncmp(ser_buf, "SET,", 4) == 0) {
                    prefs.begin("beszel", false);
                    char *p = ser_buf + 4;
                    while (*p) {
                        while (*p == ',') p++;
                        char *eq = strchr(p, '=');
                        char *amp = strchr(p, ',');
                        if (eq && (!amp || eq < amp)) {
                            *eq = 0; char *val = eq + 1;
                            if (amp) *amp = 0;
                            size_t vl = strlen(val);
                            if (vl >= 2 &&
                                ((val[0] == '"' && val[vl-1] == '"') ||
                                 (val[0] == '\'' && val[vl-1] == '\''))) {
                                val[vl-1] = 0; val++;
                            }
                            if (strcmp(p, "hub_url") == 0) prefs.putString("hub_url", val);
                            else if (strcmp(p, "token") == 0) prefs.putString("token", val);
                            else if (strcmp(p, "ssid") == 0) prefs.putString("wifi_ssid", val);
                            else if (strcmp(p, "pass") == 0) prefs.putString("wifi_pass", val);
                            else if (strcmp(p, "name") == 0) prefs.putString("device_name", val);
                            p = amp ? amp + 1 : p + strlen(p);
                        } else break;
                    }
                    prefs.putBool("configured", true);
                    prefs.end();
                    Serial.println("Saved. Rebooting...");
                    delay(200); ESP.restart();
                }
                else if (strcmp(ser_buf, "STATUS") == 0) {
                    Serial.printf("IP: %s Heap: %d WiFi: %s WS: %s\n",
                                  WiFi.localIP().toString().c_str(), ESP.getFreeHeap(),
                                  WiFi.status() == WL_CONNECTED ? "OK" : "FAIL",
                                  connected ? "OK" : "FAIL");
                }
                else if (strcmp(ser_buf, "RESET") == 0) {
                    prefs.begin("beszel", false); prefs.clear(); prefs.end();
                    Serial.println("Reset"); delay(200); ESP.restart();
                }
                else if (strcmp(ser_buf, "RECONNECT") == 0) {
                    ws.disconnect(); connectWs();
                }
                else if (strcmp(ser_buf, "METRICS") == 0) {
                    if (connected) send_metrics(1);
                    else Serial.println("WS: Not connected");
                }
                else if (strcmp(ser_buf, "LEDBLINK") == 0) {
                    prefs.begin("beszel", false);
                    led_blink = !led_blink;
                    prefs.putBool("led_blink", led_blink);
                    prefs.end();
                    if (!led_blink) digitalWrite(LED_PIN, HIGH);
                    Serial.printf("LED: Blink %s\n", led_blink ? "ON" : "OFF");
                }
                else if (strcmp(ser_buf, "HELP") == 0) {
                    Serial.println(F("\n=== Beszel Agent Commands ===\n"));
                    Serial.println(F("STATUS"));
                    Serial.println(F("  Show: IP, free heap, WiFi & WS status"));
                    Serial.println(F("  Example: STATUS\n"));

                    Serial.println(F("SET,hub_url=<url>,token=<tok>,ssid=<ss>,pass=<pw>,name=<nm>"));
                    Serial.println(F("  Configure agent credentials and WiFi"));
                    Serial.println(F("  Example: SET,hub_url=https://hub.example.com,token=abc123,ssid=MyWiFi,pass=password123,name=ESP32-C6"));
                    Serial.println(F("  Note: Use quotes for values with spaces"));
                    Serial.println(F("  Example: SET,ssid=\"My Network\",pass=\"My Password\"\n"));

                    Serial.println(F("RESET"));
                    Serial.println(F("  Clear all config and reboot"));
                    Serial.println(F("  Example: RESET\n"));

                    Serial.println(F("RECONNECT"));
                    Serial.println(F("  Force WebSocket reconnect"));
                    Serial.println(F("  Example: RECONNECT\n"));

                    Serial.println(F("METRICS"));
                    Serial.println(F("  Send metrics manually (normally every 30s)"));
                    Serial.println(F("  Example: METRICS\n"));

                    Serial.println(F("LEDBLINK"));
                    Serial.println(F("  Toggle LED blink on/off (persisted)"));
                    Serial.println(F("  ON: LED blinks 3x when sending metrics"));
                    Serial.println(F("  OFF: LED disabled"));
                    Serial.println(F("  Example: LEDBLINK\n"));
                }

                ser_len = 0;
            }
        } else if (ser_len < 255) {
            ser_buf[ser_len++] = c;
        }
    }
}
