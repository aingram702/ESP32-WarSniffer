// ============================================================================
//  settings.h  —  Runtime configuration, persisted to NVS
// ============================================================================
#pragma once

#include <Arduino.h>
#include "config.h"

struct Settings {
    // ---- Access point ----
    char     ap_ssid[33];
    char     ap_password[65];   // "" => open network
    uint8_t  ap_channel;
    bool     ap_hidden;

    // ---- Capture ----
    bool     channel_hop;
    bool     hop_pause_on_client;  // lock to AP channel while a web client is connected
    uint16_t hop_interval_ms;
    uint8_t  fixed_channel;
    bool     channel_enabled[MAX_CHANNELS + 1];  // 1-based; [0] unused
    uint16_t snap_len;
    uint16_t ws_max_pps;

    // ---- Frame-type capture mask ----
    bool     cap_mgmt;
    bool     cap_ctrl;
    bool     cap_data;

    // ---- Filtering ----
    bool     filter_enabled;
    char     bpf[160];          // BPF-style filter expression
    bool     mac_filter_is_whitelist;
    // SSID include/exclude and MAC lists are stored separately (filter.h)

    // ---- PCAP ----
    bool     pcap_enabled;
    uint32_t pcap_max_bytes;
    bool     pcap_radiotap;     // include radiotap header (rssi/channel)

    // ---- Detection toggles ----
    bool     det_deauth;
    bool     det_evil_twin;
    bool     det_pmkid;
    bool     det_arp_spoof;
    bool     det_dns_anomaly;
    bool     det_beacon_flood;
    uint16_t det_deauth_threshold;
    uint16_t det_beacon_threshold;

    // ---- Cleartext credential harvesting (unencrypted traffic only) ----
    bool     cred_harvest;

    // ---- Geolocation tagging ----
    bool     geo_enabled;
    double   geo_lat;
    double   geo_lon;
    char     geo_label[32];

    void setDefaults();
};

class SettingsStore {
public:
    static SettingsStore& instance();

    bool      begin();          // load from NVS (applies defaults if empty)
    bool      save();           // persist current settings to NVS
    void      factoryReset();   // wipe NVS and reload defaults

    Settings& get() { return _s; }

    // True until the operator changes the default AP password (UI nag).
    bool usingDefaultPassword() const;

private:
    SettingsStore() {}
    Settings _s;
    void _load();
};
