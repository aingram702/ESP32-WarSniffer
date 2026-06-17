// ============================================================================
//  filter.h  —  Capture/display filtering
//
//  Three cooperating layers, all applied on the capture path:
//    1. Frame-type capture mask (mgmt/ctrl/data)  — from Settings
//    2. MAC allow/deny list                        — managed here, persisted
//    3. SSID include/exclude list                  — managed here, persisted
//    4. BPF-style expression                        — compiled from text
//
//  The BPF layer implements a practical subset of libpcap-style primitives
//  evaluated against decoded metadata (not raw bytes), combinable with
//  and / or / not / parentheses. Supported primitives:
//
//    type mgmt|ctrl|data            subtype beacon|deauth|probe-req|...
//    wlan host <mac>                wlan src <mac>   wlan dst <mac>
//    bssid <mac>                    proto arp|dns|dhcp|http|https|eapol
//    ip | ip6 | tcp | udp | icmp    port <n>   src port <n>   dst port <n>
//    channel <n>                    rssi <op> <n>   (op: > < >= <= == !=)
//    ssid "<text>"                  pmkid          encrypted
// ============================================================================
#pragma once

#include <Arduino.h>
#include <vector>
#include "types.h"

struct MacFilterEntry { uint8_t mac[6]; char note[24]; };

// Opaque BPF AST node (defined in filter.cpp).
struct FilterNode;

class Filter {
public:
    static Filter& instance();
    void begin();

    // ---- BPF expression ----
    // Compile `expr`. Returns true on success; on failure `errOut` (>=64) holds
    // a message and the previous expression remains active.
    bool setExpression(const char* expr, char* errOut, size_t errLen);
    const char* expression() const { return _expr.c_str(); }
    bool hasExpression() const { return _root != nullptr; }

    // ---- MAC list (whitelist or blacklist, per Settings.mac_filter_is_whitelist)
    bool addMac(const uint8_t mac[6], const char* note);
    bool removeMac(const uint8_t mac[6]);
    const std::vector<MacFilterEntry>& macList() const { return _macs; }
    void clearMacs();

    // ---- SSID list ----
    bool addSsid(const char* ssid, bool exclude);  // exclude=false => include
    bool removeSsid(const char* ssid);
    void clearSsids();
    struct SsidEntry { String ssid; bool exclude; };
    const std::vector<SsidEntry>& ssidList() const { return _ssids; }

    // Evaluate all active layers. Returns true if the frame should be kept.
    bool matches(const ParsedFrame& f) const;

    bool load();   // from /filters.json
    bool save();   // to   /filters.json

private:
    Filter() {}

    // ---- BPF AST ----
    FilterNode* _root = nullptr;
    String      _expr;

    std::vector<MacFilterEntry> _macs;
    std::vector<SsidEntry>      _ssids;

    bool   evalNode(const FilterNode* n, const ParsedFrame& f) const;
    void   freeNode(FilterNode* n);
    bool   passMacList(const ParsedFrame& f) const;
    bool   passSsidList(const ParsedFrame& f) const;
};
