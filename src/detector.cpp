// ============================================================================
//  detector.cpp
// ============================================================================
#include "detector.h"
#include "settings.h"
#include "statistics.h"
#include <esp_timer.h>

Detectors& Detectors::instance() { static Detectors d; return d; }

void Detectors::begin() {
    _mtx = xSemaphoreCreateMutex();
}

void Detectors::raise(uint8_t type, uint8_t sev, const uint8_t bssid[6],
                      const uint8_t sta[6], uint8_t ch, const char* detail) {
    xSemaphoreTake(_mtx, portMAX_DELAY);
    Alert& a = _alerts[_alertHead];
    a.id = ++_alertTotal;
    a.timestamp_us = esp_timer_get_time();
    a.type = type;
    a.severity = sev;
    if (bssid) memcpy(a.bssid, bssid, 6); else memset(a.bssid, 0, 6);
    if (sta)   memcpy(a.station, sta, 6); else memset(a.station, 0, 6);
    a.channel = ch;
    strlcpy(a.detail, detail ? detail : "", sizeof(a.detail));
    _alertHead = (_alertHead + 1) % DET_MAX_ALERTS;
    _lastActiveId = a.id;
    xSemaphoreGive(_mtx);
    log_w("ALERT[%u] type=%u sev=%u %s", (unsigned)a.id, type, sev, detail);
}

void Detectors::inspect(const ParsedFrame& f) {
    Settings& s = SettingsStore::instance().get();
    if (s.det_deauth)       detectDeauth(f);
    if (s.det_beacon_flood) detectBeaconFlood(f);
    if (s.det_evil_twin)    detectEvilTwin(f);
    if (s.det_pmkid)        detectPmkid(f);
    if (s.det_arp_spoof)    detectArpSpoof(f);
    if (s.det_dns_anomaly)  detectDnsAnomaly(f);
}

// ---------------------------------------------------------------------------
//  Deauth / disassoc flood
// ---------------------------------------------------------------------------
void Detectors::detectDeauth(const ParsedFrame& f) {
    if (f.type != FRAME_TYPE_MGMT) return;
    if (f.subtype != MGMT_DEAUTH && f.subtype != MGMT_DISASSOC) return;
    const uint8_t* bssid = f.has_addr3 ? f.addr3 : f.addr1;
    uint32_t now = millis();
    uint16_t thresh = SettingsStore::instance().get().det_deauth_threshold;

    DeauthCtr* slot = nullptr;
    for (auto& c : _deauth) {
        if (c.used && mac_equal(c.bssid, bssid)) { slot = &c; break; }
        if (!c.used && !slot) slot = &c;
    }
    if (!slot) { slot = &_deauth[0]; for (auto& c : _deauth) if (c.winStart < slot->winStart) slot = &c; }
    if (!slot->used || !mac_equal(slot->bssid, bssid)) {
        memset(slot, 0, sizeof(*slot));
        slot->used = true; memcpy(slot->bssid, bssid, 6); slot->winStart = now;
    }
    if (now - slot->winStart > DET_DEAUTH_WINDOW_MS) { slot->winStart = now; slot->count = 0; }
    slot->count++;
    if (slot->count >= thresh && now - slot->lastAlert > 3000) {
        slot->lastAlert = now;
        char buf[96], m[18]; mac_to_str(bssid, m);
        snprintf(buf, sizeof(buf), "%u deauth/disassoc in 1s targeting/from %s", slot->count, m);
        raise(ALERT_DEAUTH_FLOOD, SEV_CRITICAL, bssid, f.has_addr2 ? f.addr2 : nullptr, f.channel, buf);
    }
}

// ---------------------------------------------------------------------------
//  Beacon flood (many distinct SSIDs/BSSIDs per window)
// ---------------------------------------------------------------------------
void Detectors::detectBeaconFlood(const ParsedFrame& f) {
    if (f.type != FRAME_TYPE_MGMT || f.subtype != MGMT_BEACON) return;
    uint32_t now = millis();
    uint16_t thresh = SettingsStore::instance().get().det_beacon_threshold;
    if (now - _beaconWinStart > DET_BEACON_FLOOD_WINDOW_MS) {
        _beaconWinStart = now; _beaconUnique = 0;
    }
    _beaconUnique++;   // approximate: beacon rate in window
    if (_beaconUnique == thresh) {
        char buf[96];
        snprintf(buf, sizeof(buf), "Beacon flood: %u beacons/s (possible fake-AP spam)", _beaconUnique);
        raise(ALERT_BEACON_FLOOD, SEV_WARNING, f.has_addr3 ? f.addr3 : nullptr, nullptr, f.channel, buf);
    }
}

// ---------------------------------------------------------------------------
//  Evil-twin: same SSID advertised by a different BSSID
// ---------------------------------------------------------------------------
void Detectors::detectEvilTwin(const ParsedFrame& f) {
    if (f.type != FRAME_TYPE_MGMT) return;
    if (f.subtype != MGMT_BEACON && f.subtype != MGMT_PROBE_RESP) return;
    if (f.ssid_len == 0 || !f.has_addr3) return;

    ApInfo other;
    if (Statistics::instance().findApBySsidOtherBssid(f.ssid, f.addr3, other)) {
        uint32_t now = millis();
        if (now - _evilTwinRl < 5000) return;      // global rate-limit
        _evilTwinRl = now;
        char buf[96], a[18], b[18];
        mac_to_str(f.addr3, a); mac_to_str(other.bssid, b);
        snprintf(buf, sizeof(buf), "SSID '%s' on %s also seen on %s", f.ssid, a, b);
        raise(ALERT_EVIL_TWIN, SEV_WARNING, f.addr3, nullptr, f.channel, buf);
    }
}

// ---------------------------------------------------------------------------
//  PMKID exposure
// ---------------------------------------------------------------------------
void Detectors::detectPmkid(const ParsedFrame& f) {
    if (!f.has_pmkid) return;
    const uint8_t* bssid = f.has_addr3 ? f.addr3 : f.addr2;
    char buf[96], m[18]; mac_to_str(bssid, m);
    snprintf(buf, sizeof(buf), "PMKID present in EAPOL M1 from %s (offline-crackable)", m);
    raise(ALERT_PMKID, SEV_CRITICAL, bssid, f.addr1, f.channel, buf);
}

// ---------------------------------------------------------------------------
//  ARP spoofing: an IP that resolves to a new/conflicting MAC
// ---------------------------------------------------------------------------
void Detectors::detectArpSpoof(const ParsedFrame& f) {
    if (f.l3 != L3_ARP || f.arp_op == 0) return;
    // sender ip 0.0.0.0 => ARP probe, ignore
    if ((f.arp_sender_ip[0] | f.arp_sender_ip[1] | f.arp_sender_ip[2] | f.arp_sender_ip[3]) == 0) return;

    uint32_t now = millis();
    IpBind* slot = nullptr;
    for (auto& b : _arp) {
        if (b.used && memcmp(b.ip, f.arp_sender_ip, 4) == 0) { slot = &b; break; }
        if (!b.used && !slot) slot = &b;
    }
    if (!slot) { slot = &_arp[0]; for (auto& b : _arp) if (b.lastSeen < slot->lastSeen) slot = &b; }

    if (slot->used && memcmp(slot->ip, f.arp_sender_ip, 4) == 0) {
        if (!mac_equal(slot->mac, f.arp_sender_mac)) {
            char buf[96], oldm[18], newm[18];
            mac_to_str(slot->mac, oldm); mac_to_str(f.arp_sender_mac, newm);
            snprintf(buf, sizeof(buf), "ARP: %u.%u.%u.%u moved %s -> %s",
                     f.arp_sender_ip[0], f.arp_sender_ip[1], f.arp_sender_ip[2],
                     f.arp_sender_ip[3], oldm, newm);
            raise(ALERT_ARP_SPOOF, SEV_WARNING, nullptr, f.arp_sender_mac, f.channel, buf);
            memcpy(slot->mac, f.arp_sender_mac, 6);
        }
    } else {
        memset(slot, 0, sizeof(*slot));
        slot->used = true;
        memcpy(slot->ip, f.arp_sender_ip, 4);
        memcpy(slot->mac, f.arp_sender_mac, 6);
    }
    slot->lastSeen = now;
}

// ---------------------------------------------------------------------------
//  DNS anomaly (heuristic): multiple distinct hosts answering on port 53
// ---------------------------------------------------------------------------
void Detectors::detectDnsAnomaly(const ParsedFrame& f) {
    if (f.app != APP_DNS || !f.dns_is_response || !f.has_addr2) return;
    uint32_t now = millis();
    // track distinct responder MACs over a rolling window
    DnsResp* slot = nullptr;
    uint8_t active = 0;
    for (auto& d : _dns) {
        if (d.used && now - d.lastSeen > 10000) d.used = false;   // expire
        if (d.used) active++;
        if (d.used && mac_equal(d.mac, f.addr2)) { slot = &d; break; }
        if (!d.used && !slot) slot = &d;
    }
    if (slot && !slot->used) {
        slot->used = true; memcpy(slot->mac, f.addr2, 6);
        active++;
        if (active >= 3) {   // >=3 distinct DNS responders in 10s is suspicious
            char buf[96];
            snprintf(buf, sizeof(buf), "%u distinct DNS responders in 10s (possible spoofing)", active);
            raise(ALERT_DNS_ANOMALY, SEV_WARNING, nullptr, f.addr2, f.channel, buf);
        }
    }
    if (slot) slot->lastSeen = now;
}

// ---------------------------------------------------------------------------
void Detectors::tick() {
    // window rolls are handled lazily inside each detector; nothing global yet.
}

uint32_t Detectors::alertCount() { return _alertTotal; }

uint16_t Detectors::recentAlerts(Alert* out, uint16_t max, uint32_t sinceId) {
    xSemaphoreTake(_mtx, portMAX_DELAY);
    uint16_t n = 0;
    uint32_t stored = _alertTotal < DET_MAX_ALERTS ? _alertTotal : DET_MAX_ALERTS;
    uint32_t start = (_alertTotal < DET_MAX_ALERTS) ? 0 : _alertHead;
    for (uint32_t i = 0; i < stored && n < max; i++) {
        uint32_t idx = (start + i) % DET_MAX_ALERTS;
        if (_alerts[idx].id > sinceId) out[n++] = _alerts[idx];
    }
    xSemaphoreGive(_mtx);
    return n;
}

bool Detectors::lastAlert(Alert& out) {
    if (_alertTotal == 0) return false;
    xSemaphoreTake(_mtx, portMAX_DELAY);
    uint32_t idx = (_alertHead + DET_MAX_ALERTS - 1) % DET_MAX_ALERTS;
    out = _alerts[idx];
    xSemaphoreGive(_mtx);
    return true;
}

void Detectors::clearAlerts() {
    xSemaphoreTake(_mtx, portMAX_DELAY);
    _alertHead = 0;
    // keep _alertTotal monotonic for cursor stability
    memset(_alerts, 0, sizeof(_alerts));
    xSemaphoreGive(_mtx);
}
