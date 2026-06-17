// ============================================================================
//  statistics.h  —  Traffic stats, device inventory, fingerprinting, RSSI
//
//  Maintains:
//    * global + per-channel + per-protocol counters and a packets/sec history
//    * an AP table (BSSID -> SSID, channel, privacy, RSSI envelope, beacons)
//    * a station table (MAC -> RSSI, frames, association, probed SSIDs)
//  These feed the dashboard and are queried by the detectors (evil-twin etc.).
//  All tables are fixed-capacity (no heap churn on the capture path).
// ============================================================================
#pragma once

#include <Arduino.h>
#include "types.h"
#include "config.h"

struct ApInfo {
    bool     used;
    uint8_t  bssid[6];
    char     ssid[33];
    uint8_t  channel;
    int8_t   rssi;
    int8_t   rssi_min;
    int8_t   rssi_max;
    bool     privacy;          // encryption (capability bit / protected data)
    uint32_t beacons;
    uint32_t first_seen_ms;
    uint32_t last_seen_ms;
    char     vendor[24];
};

struct StaInfo {
    bool     used;
    uint8_t  mac[6];
    int8_t   rssi;
    uint32_t frames;
    uint8_t  bssid[6];         // associated AP (if known)
    bool     associated;
    bool     randomized;       // locally-administered MAC
    uint32_t last_seen_ms;
    char     vendor[24];
    char     last_probe[33];   // most recent probed SSID (fingerprinting)
    uint16_t probe_count;
};

struct GlobalStats {
    uint64_t frames_total;
    uint64_t bytes_total;
    uint64_t mgmt, ctrl, data;
    uint64_t arp, dns, dhcp, http, https, eapol, ipv4, ipv6;
    uint64_t encrypted;
    uint64_t dropped;          // dropped on capture queue overflow
    uint32_t per_channel[MAX_CHANNELS + 1];
    uint16_t pps_history[60];  // last 60 seconds of packets/sec
    uint8_t  pps_head;
    uint16_t pps_current;      // running count this second
};

class Statistics {
public:
    static Statistics& instance();
    void begin();

    void ingest(const ParsedFrame& f);
    void noteDropped() { _g.dropped++; }
    void tickSecond();            // roll pps history (call ~1 Hz)

    const GlobalStats& global() const { return _g; }

    // Snapshot helpers (copy under lock for the web layer).
    uint16_t apCount();
    uint16_t staCount();
    bool     apAt(uint16_t i, ApInfo& out);
    bool     staAt(uint16_t i, StaInfo& out);

    // Evil-twin support: find an existing AP advertising `ssid` with a
    // *different* BSSID. Returns true and fills `out` if found.
    bool findApBySsidOtherBssid(const char* ssid, const uint8_t bssid[6], ApInfo& out);

    void reset();

private:
    Statistics() {}
    ApInfo*  _findOrAddAp(const uint8_t bssid[6]);
    StaInfo* _findOrAddSta(const uint8_t mac[6]);

    GlobalStats _g{};
    ApInfo  _aps[DET_MAX_TRACKED_APS]{};
    StaInfo _stas[DET_MAX_TRACKED_STAS]{};
    SemaphoreHandle_t _mtx = nullptr;
};
