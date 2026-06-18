// ============================================================================
//  types.h  —  Shared data types for ESP32-WarSniffer
//
//  Defines the on-wire 802.11 structures, the trimmed "captured frame" record
//  stored in the ring buffer, and the parsed metadata produced by the frame
//  parser and consumed by the detectors / statistics / web layers.
// ============================================================================
#pragma once

#include <Arduino.h>
#include <stdint.h>

// ---------------------------------------------------------------------------
//  802.11 frame control field decode helpers
// ---------------------------------------------------------------------------
enum FrameType : uint8_t {
    FRAME_TYPE_MGMT = 0,
    FRAME_TYPE_CTRL = 1,
    FRAME_TYPE_DATA = 2,
    FRAME_TYPE_EXT  = 3,
};

// Management subtypes
enum MgmtSubtype : uint8_t {
    MGMT_ASSOC_REQ    = 0,
    MGMT_ASSOC_RESP   = 1,
    MGMT_REASSOC_REQ  = 2,
    MGMT_REASSOC_RESP = 3,
    MGMT_PROBE_REQ    = 4,
    MGMT_PROBE_RESP   = 5,
    MGMT_BEACON       = 8,
    MGMT_ATIM         = 9,
    MGMT_DISASSOC     = 10,
    MGMT_AUTH         = 11,
    MGMT_DEAUTH       = 12,
    MGMT_ACTION       = 13,
};

// 802.11 MAC header (without QoS/HT control). 24 bytes for 3-address frames.
struct __attribute__((packed)) Dot11Header {
    uint16_t frame_control;
    uint16_t duration_id;
    uint8_t  addr1[6];   // receiver / destination
    uint8_t  addr2[6];   // transmitter / source
    uint8_t  addr3[6];   // bssid / etc
    uint16_t seq_ctrl;
    // addr4 (optional, WDS) and body follow
};

// esp_wifi promiscuous RX control comes in via wifi_promiscuous_pkt_t; we copy
// the relevant bits into this metadata struct on the capture path.

// L3/L4 protocol classification used by protocol filtering & stats.
enum L3Proto : uint8_t {
    L3_NONE = 0,
    L3_ARP,
    L3_IPV4,
    L3_IPV6,
    L3_EAPOL,      // 802.1X / EAPOL (WPA handshake, PMKID)
    L3_OTHER,
};

enum L4Proto : uint8_t {
    L4_NONE = 0,
    L4_TCP,
    L4_UDP,
    L4_ICMP,
    L4_OTHER,
};

// Higher-level app protocol hints (best-effort, port/heuristic based).
enum AppProto : uint8_t {
    APP_NONE = 0,
    APP_DNS,
    APP_DHCP,
    APP_HTTP,
    APP_HTTPS,
    APP_MDNS,
    APP_OTHER,
};

// ---------------------------------------------------------------------------
//  Parsed metadata for a single frame (decoded once on capture)
// ---------------------------------------------------------------------------
struct ParsedFrame {
    uint64_t  timestamp_us;     // microseconds since boot (mapped to epoch on export)
    int8_t    rssi;             // dBm
    uint8_t   channel;          // 1-14
    uint16_t  length;           // original on-air length (bytes)

    uint8_t   type;             // FrameType
    uint8_t   subtype;          // type-specific subtype
    bool      to_ds;
    bool      from_ds;
    bool      protected_frame;  // WEP/WPA encrypted bit

    uint8_t   addr1[6];
    uint8_t   addr2[6];
    uint8_t   addr3[6];
    bool      has_addr2;
    bool      has_addr3;

    // Management-frame extras
    char      ssid[33];         // null-terminated, "" if none/hidden
    uint8_t   ssid_len;
    bool      privacy;          // beacon/probe-resp capability "privacy" bit

    // Data-frame L3/L4 classification
    uint8_t   l3;               // L3Proto
    uint8_t   l4;               // L4Proto
    uint8_t   app;              // AppProto
    uint16_t  src_port;
    uint16_t  dst_port;
    bool      is_eapol;
    bool      has_pmkid;        // EAPOL message 1 carried a PMKID

    // ARP (when l3 == L3_ARP)
    uint8_t   arp_op;           // 0 = none, 1 = request, 2 = reply
    uint8_t   arp_sender_mac[6];
    uint8_t   arp_sender_ip[4];
    uint8_t   arp_target_ip[4];

    // DNS (when app == APP_DNS)
    bool      dns_is_response;
    uint16_t  dns_answers;

    // IPv4 addressing + L7 payload location (within the captured buffer)
    uint8_t   ipv4_src[4];
    uint8_t   ipv4_dst[4];
    uint16_t  l7_off;          // offset of TCP/UDP payload in frame buffer (0 = none)
    uint16_t  l7_len;          // bytes of L7 payload available in the capture
};

// ---------------------------------------------------------------------------
//  Captured frame record stored in the ring buffer (PSRAM)
// ---------------------------------------------------------------------------
struct CapturedFrame {
    ParsedFrame meta;
    uint16_t    cap_len;        // bytes actually stored in `data`
    uint8_t*    data;           // snap-length copy of raw frame (owned by ring)
};

// ---------------------------------------------------------------------------
//  IDS alert
// ---------------------------------------------------------------------------
enum AlertType : uint8_t {
    ALERT_NONE = 0,
    ALERT_DEAUTH_FLOOD,
    ALERT_EVIL_TWIN,
    ALERT_PMKID,
    ALERT_ARP_SPOOF,
    ALERT_DNS_ANOMALY,
    ALERT_BEACON_FLOOD,
    ALERT_KARMA_PROBE,
};

enum AlertSeverity : uint8_t {
    SEV_INFO = 0,
    SEV_WARNING,
    SEV_CRITICAL,
};

struct Alert {
    uint32_t      id;
    uint64_t      timestamp_us;
    uint8_t       type;          // AlertType
    uint8_t       severity;      // AlertSeverity
    uint8_t       bssid[6];
    uint8_t       station[6];
    uint8_t       channel;
    char          detail[96];    // human-readable description
};

// ---------------------------------------------------------------------------
//  MAC address helpers
// ---------------------------------------------------------------------------
inline bool mac_equal(const uint8_t a[6], const uint8_t b[6]) {
    return memcmp(a, b, 6) == 0;
}
inline bool mac_is_broadcast(const uint8_t a[6]) {
    return a[0] == 0xFF && a[1] == 0xFF && a[2] == 0xFF &&
           a[3] == 0xFF && a[4] == 0xFF && a[5] == 0xFF;
}
inline bool mac_is_zero(const uint8_t a[6]) {
    return (a[0] | a[1] | a[2] | a[3] | a[4] | a[5]) == 0;
}
// Format MAC into caller-provided buffer (>=18 bytes). Returns buf.
inline char* mac_to_str(const uint8_t a[6], char* buf) {
    snprintf(buf, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             a[0], a[1], a[2], a[3], a[4], a[5]);
    return buf;
}
// Parse "aa:bb:cc:dd:ee:ff" -> out[6]. Returns true on success.
bool mac_from_str(const char* s, uint8_t out[6]);
