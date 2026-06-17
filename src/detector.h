// ============================================================================
//  detector.h  —  On-device intrusion / anomaly detection
//
//  Each detector is independently toggleable (Settings). Findings are written
//  to a fixed-size alert ring buffer with per-source rate-limiting so a single
//  attack does not flood the UI. Detectors:
//
//    * Deauth / disassoc flood   (rate per BSSID)
//    * Beacon flood               (unique SSIDs per window)
//    * Evil-twin AP               (same SSID, different BSSID, RSSI delta)
//    * PMKID exposure             (EAPOL M1 carrying RSN PMKID KDE)
//    * ARP spoofing               (IP->MAC binding changes / conflicts)
//    * DNS anomaly                (heuristic: multiple responders / spikes)
// ============================================================================
#pragma once

#include <Arduino.h>
#include "types.h"
#include "config.h"

class Detectors {
public:
    static Detectors& instance();
    void begin();

    // Run all enabled detectors against a parsed frame.
    void inspect(const ParsedFrame& f);

    void tick();   // periodic window roll / housekeeping (call ~1 Hz)

    // Alert access for the web layer.
    uint32_t alertCount();                       // total raised since boot
    uint16_t recentAlerts(Alert* out, uint16_t max, uint32_t sinceId);
    bool     lastAlert(Alert& out);
    uint32_t activeAlertId() const { return _lastActiveId; }
    void     clearAlerts();

private:
    Detectors() {}
    void raise(uint8_t type, uint8_t sev, const uint8_t bssid[6],
               const uint8_t sta[6], uint8_t ch, const char* detail);

    // ---- detector state ----
    struct DeauthCtr { uint8_t bssid[6]; uint16_t count; uint32_t winStart; uint32_t lastAlert; bool used; };
    struct IpBind    { uint8_t ip[4]; uint8_t mac[6]; uint32_t lastSeen; bool used; };
    struct DnsResp   { uint8_t mac[6]; uint32_t lastSeen; bool used; };

    DeauthCtr _deauth[DET_MAX_TRACKED_APS]{};
    IpBind    _arp[128]{};
    DnsResp   _dns[16]{};

    uint16_t  _beaconUnique = 0;
    uint32_t  _beaconWinStart = 0;
    uint32_t  _evilTwinRl = 0;     // simple global rate-limit timestamp

    // ---- alert ring ----
    Alert     _alerts[DET_MAX_ALERTS]{};
    uint32_t  _alertHead = 0;
    uint32_t  _alertTotal = 0;
    uint32_t  _lastActiveId = 0;
    SemaphoreHandle_t _mtx = nullptr;

    void detectDeauth(const ParsedFrame& f);
    void detectBeaconFlood(const ParsedFrame& f);
    void detectEvilTwin(const ParsedFrame& f);
    void detectPmkid(const ParsedFrame& f);
    void detectArpSpoof(const ParsedFrame& f);
    void detectDnsAnomaly(const ParsedFrame& f);
};
