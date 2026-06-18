// ============================================================================
//  settings.cpp
// ============================================================================
#include "settings.h"
#include <Preferences.h>

// ---- types.h helper that needs a .cpp home ----
bool mac_from_str(const char* s, uint8_t out[6]) {
    if (!s) return false;
    int v[6];
    if (sscanf(s, "%x:%x:%x:%x:%x:%x",
               &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]) != 6) {
        return false;
    }
    for (int i = 0; i < 6; i++) {
        if (v[i] < 0 || v[i] > 0xFF) return false;
        out[i] = (uint8_t)v[i];
    }
    return true;
}

void Settings::setDefaults() {
    memset(this, 0, sizeof(*this));

    strlcpy(ap_ssid, DEFAULT_AP_SSID, sizeof(ap_ssid));
    strlcpy(ap_password, DEFAULT_AP_PASSWORD, sizeof(ap_password));
    ap_channel = DEFAULT_AP_CHANNEL;
    ap_hidden  = DEFAULT_AP_HIDDEN;

    channel_hop         = DEFAULT_CHANNEL_HOP;
    hop_pause_on_client = true;
    hop_interval_ms = DEFAULT_HOP_INTERVAL_MS;
    fixed_channel   = DEFAULT_CHANNEL;
    for (int ch = CHANNEL_MIN; ch <= CHANNEL_MAX; ch++) {
        channel_enabled[ch] = (ch <= 13);   // 1-13 on by default
    }
    snap_len   = DEFAULT_SNAP_LEN;
    ws_max_pps = DEFAULT_WS_MAX_PPS;

    cap_mgmt = true;
    cap_ctrl = true;
    cap_data = true;

    filter_enabled = false;
    bpf[0] = '\0';
    mac_filter_is_whitelist = false;

    pcap_enabled   = false;
    pcap_max_bytes = DEFAULT_PCAP_MAX_BYTES;
    pcap_radiotap  = true;

    det_deauth        = true;
    det_evil_twin     = true;
    det_pmkid         = true;
    det_arp_spoof     = true;
    det_dns_anomaly   = true;
    det_beacon_flood  = true;
    det_deauth_threshold = DET_DEAUTH_THRESHOLD;
    det_beacon_threshold = DET_BEACON_FLOOD_THRESHOLD;

    cred_harvest = true;

    geo_enabled = false;
    geo_lat = 0.0;
    geo_lon = 0.0;
    geo_label[0] = '\0';
}

SettingsStore& SettingsStore::instance() {
    static SettingsStore s;
    return s;
}

bool SettingsStore::begin() {
    _load();
    return true;
}

void SettingsStore::_load() {
    Preferences p;
    _s.setDefaults();
    if (!p.begin(NVS_NAMESPACE, true)) {
        // namespace doesn't exist yet -> keep defaults
        return;
    }
    size_t got = p.getBytesLength("blob");
    if (got == sizeof(Settings)) {
        Settings tmp;
        p.getBytes("blob", &tmp, sizeof(tmp));
        _s = tmp;
    }
    p.end();
}

bool SettingsStore::save() {
    Preferences p;
    if (!p.begin(NVS_NAMESPACE, false)) return false;
    size_t w = p.putBytes("blob", &_s, sizeof(_s));
    p.end();
    return w == sizeof(_s);
}

void SettingsStore::factoryReset() {
    Preferences p;
    if (p.begin(NVS_NAMESPACE, false)) {
        p.clear();
        p.end();
    }
    _s.setDefaults();
    save();
}

bool SettingsStore::usingDefaultPassword() const {
    return strcmp(_s.ap_password, DEFAULT_AP_PASSWORD) == 0;
}
