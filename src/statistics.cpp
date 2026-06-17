// ============================================================================
//  statistics.cpp
// ============================================================================
#include "statistics.h"
#include "oui_lookup.h"

Statistics& Statistics::instance() { static Statistics s; return s; }

void Statistics::begin() {
    _mtx = xSemaphoreCreateMutex();
    reset();
}

void Statistics::reset() {
    if (_mtx) xSemaphoreTake(_mtx, portMAX_DELAY);
    memset(&_g, 0, sizeof(_g));
    memset(_aps, 0, sizeof(_aps));
    memset(_stas, 0, sizeof(_stas));
    if (_mtx) xSemaphoreGive(_mtx);
}

// --- table helpers (caller holds lock) ---
ApInfo* Statistics::_findOrAddAp(const uint8_t bssid[6]) {
    for (auto& a : _aps) if (a.used && mac_equal(a.bssid, bssid)) return &a;
    // pick a free slot or evict the oldest
    ApInfo* slot = nullptr;
    for (auto& a : _aps) if (!a.used) { slot = &a; break; }
    if (!slot) {
        slot = &_aps[0];
        for (auto& a : _aps) if (a.last_seen_ms < slot->last_seen_ms) slot = &a;
    }
    memset(slot, 0, sizeof(*slot));
    slot->used = true;
    memcpy(slot->bssid, bssid, 6);
    slot->rssi_min = 127; slot->rssi_max = -128;
    slot->first_seen_ms = millis();
    char v[24]; OuiLookup::instance().lookup(bssid, v, sizeof(v));
    strlcpy(slot->vendor, v, sizeof(slot->vendor));
    return slot;
}

StaInfo* Statistics::_findOrAddSta(const uint8_t mac[6]) {
    for (auto& s : _stas) if (s.used && mac_equal(s.mac, mac)) return &s;
    StaInfo* slot = nullptr;
    for (auto& s : _stas) if (!s.used) { slot = &s; break; }
    if (!slot) {
        slot = &_stas[0];
        for (auto& s : _stas) if (s.last_seen_ms < slot->last_seen_ms) slot = &s;
    }
    memset(slot, 0, sizeof(*slot));
    slot->used = true;
    memcpy(slot->mac, mac, 6);
    slot->randomized = (mac[0] & 0x02);
    char v[24]; OuiLookup::instance().lookup(mac, v, sizeof(v));
    strlcpy(slot->vendor, v, sizeof(slot->vendor));
    return slot;
}

void Statistics::ingest(const ParsedFrame& f) {
    if (!_mtx) return;
    xSemaphoreTake(_mtx, portMAX_DELAY);

    _g.frames_total++;
    _g.bytes_total += f.length;
    _g.pps_current++;
    if (f.channel >= 1 && f.channel <= MAX_CHANNELS) _g.per_channel[f.channel]++;

    switch (f.type) {
        case FRAME_TYPE_MGMT: _g.mgmt++; break;
        case FRAME_TYPE_CTRL: _g.ctrl++; break;
        case FRAME_TYPE_DATA: _g.data++; break;
    }
    if (f.protected_frame) _g.encrypted++;
    switch (f.l3) {
        case L3_ARP:   _g.arp++;  break;
        case L3_IPV4:  _g.ipv4++; break;
        case L3_IPV6:  _g.ipv6++; break;
        case L3_EAPOL: _g.eapol++; break;
    }
    switch (f.app) {
        case APP_DNS:   _g.dns++;   break;
        case APP_DHCP:  _g.dhcp++;  break;
        case APP_HTTP:  _g.http++;  break;
        case APP_HTTPS: _g.https++; break;
    }

    uint32_t now = millis();

    // ---- AP tracking from beacons / probe responses ----
    if (f.type == FRAME_TYPE_MGMT &&
        (f.subtype == MGMT_BEACON || f.subtype == MGMT_PROBE_RESP) && f.has_addr3) {
        ApInfo* ap = _findOrAddAp(f.addr3);
        ap->channel = f.channel;
        ap->rssi = f.rssi;
        if (f.rssi < ap->rssi_min) ap->rssi_min = f.rssi;
        if (f.rssi > ap->rssi_max) ap->rssi_max = f.rssi;
        if (f.subtype == MGMT_BEACON) ap->beacons++;
        if (f.ssid_len) strlcpy(ap->ssid, f.ssid, sizeof(ap->ssid));
        ap->privacy = f.privacy;
        ap->last_seen_ms = now;
    }

    // ---- Station tracking ----
    // Probe requests reveal a client and the SSID it's looking for.
    if (f.type == FRAME_TYPE_MGMT && f.subtype == MGMT_PROBE_REQ && f.has_addr2) {
        StaInfo* st = _findOrAddSta(f.addr2);
        st->rssi = f.rssi;
        st->frames++;
        st->last_seen_ms = now;
        if (f.ssid_len) { strlcpy(st->last_probe, f.ssid, sizeof(st->last_probe)); st->probe_count++; }
    }
    // Data frames: the non-AP address is a station; addr3 often the BSSID.
    if (f.type == FRAME_TYPE_DATA && f.has_addr2) {
        const uint8_t* sta = nullptr;
        const uint8_t* bss = nullptr;
        if (f.to_ds && !f.from_ds)      { sta = f.addr2; bss = f.addr1; }
        else if (!f.to_ds && f.from_ds) { sta = f.addr1; bss = f.addr2; }
        if (sta && !mac_is_broadcast(sta) && !(sta[0] & 0x01)) {
            StaInfo* st = _findOrAddSta(sta);
            st->rssi = f.rssi;
            st->frames++;
            st->last_seen_ms = now;
            if (bss && f.has_addr3) { memcpy(st->bssid, bss, 6); st->associated = true; }
            if (f.protected_frame) { /* associated AP likely has privacy */ }
        }
    }

    xSemaphoreGive(_mtx);
}

void Statistics::tickSecond() {
    if (!_mtx) return;
    xSemaphoreTake(_mtx, portMAX_DELAY);
    _g.pps_history[_g.pps_head] = _g.pps_current;
    _g.pps_head = (_g.pps_head + 1) % 60;
    _g.pps_current = 0;
    xSemaphoreGive(_mtx);
}

uint16_t Statistics::apCount() {
    xSemaphoreTake(_mtx, portMAX_DELAY);
    uint16_t n = 0; for (auto& a : _aps) if (a.used) n++;
    xSemaphoreGive(_mtx);
    return n;
}
uint16_t Statistics::staCount() {
    xSemaphoreTake(_mtx, portMAX_DELAY);
    uint16_t n = 0; for (auto& s : _stas) if (s.used) n++;
    xSemaphoreGive(_mtx);
    return n;
}
bool Statistics::apAt(uint16_t i, ApInfo& out) {
    bool ok = false;
    xSemaphoreTake(_mtx, portMAX_DELAY);
    uint16_t n = 0;
    for (auto& a : _aps) if (a.used) { if (n == i) { out = a; ok = true; break; } n++; }
    xSemaphoreGive(_mtx);
    return ok;
}
bool Statistics::staAt(uint16_t i, StaInfo& out) {
    bool ok = false;
    xSemaphoreTake(_mtx, portMAX_DELAY);
    uint16_t n = 0;
    for (auto& s : _stas) if (s.used) { if (n == i) { out = s; ok = true; break; } n++; }
    xSemaphoreGive(_mtx);
    return ok;
}

bool Statistics::findApBySsidOtherBssid(const char* ssid, const uint8_t bssid[6], ApInfo& out) {
    if (!ssid || !*ssid) return false;
    bool ok = false;
    xSemaphoreTake(_mtx, portMAX_DELAY);
    for (auto& a : _aps) {
        if (a.used && !mac_equal(a.bssid, bssid) && strcmp(a.ssid, ssid) == 0) {
            out = a; ok = true; break;
        }
    }
    xSemaphoreGive(_mtx);
    return ok;
}
