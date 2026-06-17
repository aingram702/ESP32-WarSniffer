// ============================================================================
//  config.h  —  Compile-time defaults for ESP32-WarSniffer
//
//  Runtime-tunable values live in Settings (settings.h) and are persisted to
//  NVS so they can be changed from the web UI without re-flashing. The values
//  here are only the *defaults* applied on first boot / factory reset.
// ============================================================================
#pragma once

#include <Arduino.h>

// ---- Firmware -------------------------------------------------------------
#ifndef WARSNIFFER_VERSION
#define WARSNIFFER_VERSION "1.0.0-dev"
#endif
#define WARSNIFFER_BUILD __DATE__ " " __TIME__

// ---- Access-Point (out-of-band management) --------------------------------
// NOTE: The default password is intentionally non-trivial but MUST be changed
//       by the operator. The UI nags until it is changed. WPA2 requires >= 8
//       characters; an empty string falls back to an OPEN network (discouraged).
#define DEFAULT_AP_SSID      "WarSniffer"
#define DEFAULT_AP_PASSWORD  "sniffsniff"
#define DEFAULT_AP_CHANNEL   6
#define DEFAULT_AP_HIDDEN    false
#define DEFAULT_AP_MAX_CONN  4
#define AP_IP_ADDR           192, 168, 4, 1
#define AP_GATEWAY           192, 168, 4, 1
#define AP_SUBNET            255, 255, 255, 0

// ---- Capture engine -------------------------------------------------------
#define DEFAULT_CHANNEL          6      // starting channel when not hopping
#define DEFAULT_CHANNEL_HOP      true
#define DEFAULT_HOP_INTERVAL_MS  250    // dwell time per channel
#define CHANNEL_MIN              1
#define CHANNEL_MAX              13     // set 14 only where legally permitted
#define MAX_CHANNELS             14

// Captured-frame ring buffer (lives in PSRAM). Each slot stores a trimmed
// copy of the frame (headers + snap length of payload) plus metadata.
#define RING_CAPACITY_FRAMES     2048   // number of frame slots
#define DEFAULT_SNAP_LEN         256    // bytes of each frame retained
#define MAX_SNAP_LEN             512

// Live WebSocket stream: max frames/sec pushed to browser (back-pressure).
#define DEFAULT_WS_MAX_PPS       60

// ---- PCAP -----------------------------------------------------------------
#define PCAP_DIR                 "/pcap"
#define DEFAULT_PCAP_MAX_BYTES   (4UL * 1024 * 1024)  // rotate at 4 MB
#define PCAP_LINKTYPE_802_11     105   // LINKTYPE_IEEE802_11
#define PCAP_LINKTYPE_RADIOTAP   127   // LINKTYPE_IEEE802_11_RADIOTAP

// ---- Status LEDs ----------------------------------------------------------
// ESP32-S3-DevKitC-1 has an addressable WS2812 on GPIO48 (RGB_BUILTIN).
#ifndef WARSNIFFER_LED_PIN
#define WARSNIFFER_LED_PIN       48
#endif
#define LED_BRIGHTNESS           24     // 0-255, keep low (eye + power)

// ---- Detection / IDS thresholds (defaults, tunable at runtime) ------------
#define DET_DEAUTH_WINDOW_MS         1000
#define DET_DEAUTH_THRESHOLD         20    // deauth/disassoc frames per window
#define DET_BEACON_FLOOD_WINDOW_MS   1000
#define DET_BEACON_FLOOD_THRESHOLD   40    // unique SSIDs per window
#define DET_EVIL_TWIN_RSSI_DELTA     25    // dBm jump for same SSID, new BSSID
#define DET_MAX_TRACKED_APS          128
#define DET_MAX_TRACKED_STAS         256
#define DET_MAX_ALERTS               128   // alert ring buffer

// ---- Misc -----------------------------------------------------------------
#define NVS_NAMESPACE            "warsniffer"
#define SERIAL_BAUD              115200
#define HOSTNAME                 "warsniffer"
