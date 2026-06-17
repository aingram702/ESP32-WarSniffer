// ============================================================================
//  filter.cpp  —  MAC/SSID lists + a compact BPF-style expression engine
// ============================================================================
#include "filter.h"
#include "settings.h"
#include <LittleFS.h>
#include <ArduinoJson.h>

// ---------------------------------------------------------------------------
//  AST
// ---------------------------------------------------------------------------
enum NodeKind : uint8_t { N_AND, N_OR, N_NOT, N_PRED };
enum PredKind : uint8_t {
    P_TYPE, P_SUBTYPE, P_HOST, P_PROTO, P_IP, P_IP6,
    P_TCP, P_UDP, P_ICMP, P_PORT, P_CHANNEL, P_RSSI,
    P_SSID, P_PMKID, P_ENCRYPTED, P_TRUE
};
enum Dir : uint8_t { DIR_ANY, DIR_SRC, DIR_DST, DIR_BSSID };

struct FilterNode {
    NodeKind kind;
    FilterNode* l = nullptr;
    FilterNode* r = nullptr;
    // predicate payload
    PredKind pred;
    uint8_t  u8a = 0, u8b = 0;     // generic (type/subtype/dir/proto/op)
    uint16_t u16 = 0;              // port / channel
    int16_t  i16 = 0;              // rssi value
    uint8_t  mac[6] = {0};
    char     text[34] = {0};       // ssid
};

// ---------------------------------------------------------------------------
//  Tokenizer
// ---------------------------------------------------------------------------
namespace {

struct Tok { String s; bool isStr; };

bool tokenize(const char* expr, std::vector<Tok>& out, char* err, size_t errLen) {
    const char* p = expr;
    while (*p) {
        if (isspace((unsigned char)*p)) { p++; continue; }
        if (*p == '(' || *p == ')') { out.push_back({String(*p), false}); p++; continue; }
        if (*p == '"') {                       // quoted string (ssid)
            p++; String s;
            while (*p && *p != '"') { s += *p; p++; }
            if (*p != '"') { strlcpy(err, "unterminated string", errLen); return false; }
            p++; out.push_back({s, true}); continue;
        }
        // comparison operators
        if (*p == '>' || *p == '<' || *p == '=' || *p == '!') {
            String s; s += *p++;
            if (*p == '=') { s += *p++; }
            out.push_back({s, false}); continue;
        }
        // word / number / mac
        String s;
        while (*p && !isspace((unsigned char)*p) && *p != '(' && *p != ')' &&
               *p != '>' && *p != '<' && *p != '=' && *p != '!') {
            s += *p++;
        }
        if (s.length()) out.push_back({s, false});
    }
    return true;
}

bool eqi(const String& a, const char* b) { return a.equalsIgnoreCase(b); }

}  // namespace

// ---------------------------------------------------------------------------
//  Parser (recursive descent)
// ---------------------------------------------------------------------------
namespace {
struct Parser {
    const std::vector<Tok>& t;
    size_t i = 0;
    char*  err;
    size_t errLen;
    bool   ok = true;

    Parser(const std::vector<Tok>& toks, char* e, size_t el) : t(toks), err(e), errLen(el) {}

    bool end() { return i >= t.size(); }
    const String& peek() { static String empty; return end() ? empty : t[i].s; }
    bool peekStr() { return !end() && t[i].isStr; }
    void fail(const char* m) { if (ok) { strlcpy(err, m, errLen); ok = false; } }

    FilterNode* parseOr() {
        FilterNode* n = parseAnd();
        while (ok && !end() && eqi(peek(), "or")) {
            i++;
            FilterNode* r = parseAnd();
            FilterNode* a = new FilterNode(); a->kind = N_OR; a->l = n; a->r = r;
            n = a;
        }
        return n;
    }
    FilterNode* parseAnd() {
        FilterNode* n = parseNot();
        while (ok && !end()) {
            // implicit-and not supported; require explicit 'and'
            if (eqi(peek(), "and")) { i++; }
            else break;
            FilterNode* r = parseNot();
            FilterNode* a = new FilterNode(); a->kind = N_AND; a->l = n; a->r = r;
            n = a;
        }
        return n;
    }
    FilterNode* parseNot() {
        if (!end() && (eqi(peek(), "not") || peek() == "!")) {
            i++;
            FilterNode* c = parseNot();
            FilterNode* a = new FilterNode(); a->kind = N_NOT; a->l = c;
            return a;
        }
        return parsePrimary();
    }
    FilterNode* parsePrimary() {
        if (end()) { fail("unexpected end of expression"); return nullptr; }
        if (peek() == "(") {
            i++;
            FilterNode* n = parseOr();
            if (end() || peek() != ")") { fail("missing ')'"); return n; }
            i++;
            return n;
        }
        return parsePredicate();
    }

    bool takeMac(uint8_t out[6]) {
        if (end()) return false;
        if (!mac_from_str(peek().c_str(), out)) return false;
        i++; return true;
    }
    bool takeUint(uint32_t& v) {
        if (end()) return false;
        const String& s = peek();
        for (size_t k = 0; k < s.length(); k++) if (!isdigit((unsigned char)s[k])) return false;
        v = (uint32_t)s.toInt(); i++; return true;
    }

    FilterNode* pred() { FilterNode* n = new FilterNode(); n->kind = N_PRED; return n; }

    FilterNode* parsePredicate() {
        String k = peek();
        if (peekStr()) { fail("unexpected string literal"); return nullptr; }
        i++;

        if (eqi(k, "type")) {
            FilterNode* n = pred(); n->pred = P_TYPE;
            String v = peek(); i++;
            if (eqi(v, "mgmt")) n->u8a = FRAME_TYPE_MGMT;
            else if (eqi(v, "ctrl")) n->u8a = FRAME_TYPE_CTRL;
            else if (eqi(v, "data")) n->u8a = FRAME_TYPE_DATA;
            else { fail("type expects mgmt|ctrl|data"); }
            return n;
        }
        if (eqi(k, "subtype")) {
            FilterNode* n = pred(); n->pred = P_SUBTYPE;
            String v = peek(); i++;
            n->u8a = 0xFF;  // type wildcard
            if (eqi(v, "beacon")) n->u8b = MGMT_BEACON, n->u8a = FRAME_TYPE_MGMT;
            else if (eqi(v, "deauth")) n->u8b = MGMT_DEAUTH, n->u8a = FRAME_TYPE_MGMT;
            else if (eqi(v, "disassoc")) n->u8b = MGMT_DISASSOC, n->u8a = FRAME_TYPE_MGMT;
            else if (eqi(v, "probe-req")) n->u8b = MGMT_PROBE_REQ, n->u8a = FRAME_TYPE_MGMT;
            else if (eqi(v, "probe-resp")) n->u8b = MGMT_PROBE_RESP, n->u8a = FRAME_TYPE_MGMT;
            else if (eqi(v, "auth")) n->u8b = MGMT_AUTH, n->u8a = FRAME_TYPE_MGMT;
            else if (eqi(v, "assoc-req")) n->u8b = MGMT_ASSOC_REQ, n->u8a = FRAME_TYPE_MGMT;
            else { fail("unknown subtype"); }
            return n;
        }
        if (eqi(k, "wlan")) {
            // wlan host|src|dst <mac>
            String d = peek(); i++;
            FilterNode* n = pred(); n->pred = P_HOST;
            if (eqi(d, "host")) n->u8a = DIR_ANY;
            else if (eqi(d, "src")) n->u8a = DIR_SRC;
            else if (eqi(d, "dst")) n->u8a = DIR_DST;
            else { fail("wlan expects host|src|dst"); return n; }
            if (!takeMac(n->mac)) fail("expected MAC address");
            return n;
        }
        if (eqi(k, "bssid")) {
            FilterNode* n = pred(); n->pred = P_HOST; n->u8a = DIR_BSSID;
            if (!takeMac(n->mac)) fail("bssid expects MAC");
            return n;
        }
        if (eqi(k, "proto")) {
            FilterNode* n = pred(); n->pred = P_PROTO;
            String v = peek(); i++;
            if (eqi(v, "arp")) n->u8a = L3_ARP, n->u8b = APP_NONE;
            else if (eqi(v, "eapol")) n->u8a = L3_EAPOL, n->u8b = APP_NONE;
            else if (eqi(v, "dns")) n->u8a = 0, n->u8b = APP_DNS;
            else if (eqi(v, "dhcp")) n->u8a = 0, n->u8b = APP_DHCP;
            else if (eqi(v, "http")) n->u8a = 0, n->u8b = APP_HTTP;
            else if (eqi(v, "https")) n->u8a = 0, n->u8b = APP_HTTPS;
            else if (eqi(v, "mdns")) n->u8a = 0, n->u8b = APP_MDNS;
            else { fail("unknown proto"); }
            return n;
        }
        if (eqi(k, "ip"))  { FilterNode* n = pred(); n->pred = P_IP;  return n; }
        if (eqi(k, "ip6")) { FilterNode* n = pred(); n->pred = P_IP6; return n; }
        if (eqi(k, "tcp")) { FilterNode* n = pred(); n->pred = P_TCP; return n; }
        if (eqi(k, "udp")) { FilterNode* n = pred(); n->pred = P_UDP; return n; }
        if (eqi(k, "icmp")){ FilterNode* n = pred(); n->pred = P_ICMP; return n; }
        if (eqi(k, "pmkid")) { FilterNode* n = pred(); n->pred = P_PMKID; return n; }
        if (eqi(k, "encrypted")) { FilterNode* n = pred(); n->pred = P_ENCRYPTED; return n; }

        if (eqi(k, "port") || eqi(k, "src") || eqi(k, "dst")) {
            FilterNode* n = pred(); n->pred = P_PORT; n->u8a = DIR_ANY;
            if (eqi(k, "src") || eqi(k, "dst")) {
                n->u8a = eqi(k, "src") ? DIR_SRC : DIR_DST;
                if (!eqi(peek(), "port")) { fail("expected 'port'"); return n; }
                i++;
            }
            uint32_t v; if (!takeUint(v)) { fail("port expects number"); return n; }
            n->u16 = (uint16_t)v;
            return n;
        }
        if (eqi(k, "channel")) {
            FilterNode* n = pred(); n->pred = P_CHANNEL;
            uint32_t v; if (!takeUint(v)) { fail("channel expects number"); return n; }
            n->u16 = (uint16_t)v;
            return n;
        }
        if (eqi(k, "rssi")) {
            FilterNode* n = pred(); n->pred = P_RSSI;
            String op = peek(); i++;
            if (op == ">") n->u8a = 0; else if (op == "<") n->u8a = 1;
            else if (op == ">=") n->u8a = 2; else if (op == "<=") n->u8a = 3;
            else if (op == "==" || op == "=") n->u8a = 4; else if (op == "!=") n->u8a = 5;
            else { fail("rssi expects comparison op"); return n; }
            // value may be negative
            String num = peek(); i++;
            n->i16 = (int16_t)num.toInt();
            return n;
        }
        if (eqi(k, "ssid")) {
            FilterNode* n = pred(); n->pred = P_SSID;
            if (!peekStr()) { fail("ssid expects \"quoted\" value"); return n; }
            strlcpy(n->text, peek().c_str(), sizeof(n->text)); i++;
            return n;
        }
        fail("unknown keyword");
        return nullptr;
    }
};
}  // namespace

// ---------------------------------------------------------------------------
Filter& Filter::instance() { static Filter f; return f; }

void Filter::begin() { load(); }

bool Filter::setExpression(const char* expr, char* errOut, size_t errLen) {
    errOut[0] = '\0';
    if (!expr || !*expr) {                 // empty clears the expression
        freeNode(_root); _root = nullptr; _expr = "";
        return true;
    }
    std::vector<Tok> toks;
    if (!tokenize(expr, toks, errOut, errLen)) return false;
    if (toks.empty()) { freeNode(_root); _root = nullptr; _expr = ""; return true; }

    Parser ps(toks, errOut, errLen);
    FilterNode* root = ps.parseOr();
    if (!ps.ok || !ps.end()) {
        if (ps.ok) strlcpy(errOut, "trailing tokens", errLen);
        freeNode(root);
        return false;
    }
    freeNode(_root);
    _root = root;
    _expr = expr;
    return true;
}

void Filter::freeNode(FilterNode* n) {
    if (!n) return;
    freeNode(n->l);
    freeNode(n->r);
    delete n;
}

// ---------------------------------------------------------------------------
//  Evaluation
// ---------------------------------------------------------------------------
bool Filter::evalNode(const FilterNode* n, const ParsedFrame& f) const {
    if (!n) return true;
    switch (n->kind) {
        case N_AND: return evalNode(n->l, f) && evalNode(n->r, f);
        case N_OR:  return evalNode(n->l, f) || evalNode(n->r, f);
        case N_NOT: return !evalNode(n->l, f);
        case N_PRED: break;
    }
    switch (n->pred) {
        case P_TRUE:    return true;
        case P_TYPE:    return f.type == n->u8a;
        case P_SUBTYPE: return f.type == n->u8a && f.subtype == n->u8b;
        case P_HOST: {
            switch (n->u8a) {
                case DIR_SRC:   return f.has_addr2 && mac_equal(f.addr2, n->mac);
                case DIR_DST:   return mac_equal(f.addr1, n->mac);
                case DIR_BSSID: return f.has_addr3 && mac_equal(f.addr3, n->mac);
                default:
                    return mac_equal(f.addr1, n->mac) ||
                           (f.has_addr2 && mac_equal(f.addr2, n->mac)) ||
                           (f.has_addr3 && mac_equal(f.addr3, n->mac));
            }
        }
        case P_PROTO:
            if (n->u8b != APP_NONE) return f.app == n->u8b;
            return f.l3 == n->u8a;
        case P_IP:   return f.l3 == L3_IPV4;
        case P_IP6:  return f.l3 == L3_IPV6;
        case P_TCP:  return f.l4 == L4_TCP;
        case P_UDP:  return f.l4 == L4_UDP;
        case P_ICMP: return f.l4 == L4_ICMP;
        case P_PORT:
            switch (n->u8a) {
                case DIR_SRC: return f.src_port == n->u16;
                case DIR_DST: return f.dst_port == n->u16;
                default:      return f.src_port == n->u16 || f.dst_port == n->u16;
            }
        case P_CHANNEL:  return f.channel == n->u16;
        case P_RSSI:
            switch (n->u8a) {
                case 0: return f.rssi >  n->i16;
                case 1: return f.rssi <  n->i16;
                case 2: return f.rssi >= n->i16;
                case 3: return f.rssi <= n->i16;
                case 4: return f.rssi == n->i16;
                default:return f.rssi != n->i16;
            }
        case P_SSID:      return strcmp(f.ssid, n->text) == 0;
        case P_PMKID:     return f.has_pmkid;
        case P_ENCRYPTED: return f.protected_frame;
    }
    return true;
}

bool Filter::passMacList(const ParsedFrame& f) const {
    if (_macs.empty()) return true;
    bool whitelist = SettingsStore::instance().get().mac_filter_is_whitelist;
    bool hit = false;
    for (auto& e : _macs) {
        if (mac_equal(f.addr1, e.mac) ||
            (f.has_addr2 && mac_equal(f.addr2, e.mac)) ||
            (f.has_addr3 && mac_equal(f.addr3, e.mac))) { hit = true; break; }
    }
    return whitelist ? hit : !hit;
}

bool Filter::passSsidList(const ParsedFrame& f) const {
    if (_ssids.empty() || f.ssid_len == 0) return true;
    bool anyInclude = false, includeHit = false;
    for (auto& e : _ssids) {
        bool match = e.ssid.equals(f.ssid);
        if (e.exclude) { if (match) return false; }
        else { anyInclude = true; if (match) includeHit = true; }
    }
    // If include entries exist, the SSID (when present) must match one.
    if (anyInclude && f.ssid_len > 0) return includeHit;
    return true;
}

bool Filter::matches(const ParsedFrame& f) const {
    Settings& s = SettingsStore::instance().get();
    // frame-type capture mask
    if (f.type == FRAME_TYPE_MGMT && !s.cap_mgmt) return false;
    if (f.type == FRAME_TYPE_CTRL && !s.cap_ctrl) return false;
    if (f.type == FRAME_TYPE_DATA && !s.cap_data) return false;

    if (!s.filter_enabled) return true;
    if (!passMacList(f))  return false;
    if (!passSsidList(f)) return false;
    if (_root && !evalNode(_root, f)) return false;
    return true;
}

// ---------------------------------------------------------------------------
//  MAC / SSID list management
// ---------------------------------------------------------------------------
bool Filter::addMac(const uint8_t mac[6], const char* note) {
    for (auto& e : _macs) if (mac_equal(e.mac, mac)) return false;
    if (_macs.size() >= 64) return false;
    MacFilterEntry e{}; memcpy(e.mac, mac, 6);
    strlcpy(e.note, note ? note : "", sizeof(e.note));
    _macs.push_back(e); save(); return true;
}
bool Filter::removeMac(const uint8_t mac[6]) {
    for (size_t i = 0; i < _macs.size(); i++) {
        if (mac_equal(_macs[i].mac, mac)) { _macs.erase(_macs.begin() + i); save(); return true; }
    }
    return false;
}
void Filter::clearMacs() { _macs.clear(); save(); }

bool Filter::addSsid(const char* ssid, bool exclude) {
    if (!ssid || !*ssid) return false;
    for (auto& e : _ssids) if (e.ssid.equals(ssid)) { e.exclude = exclude; save(); return true; }
    if (_ssids.size() >= 64) return false;
    _ssids.push_back({String(ssid), exclude}); save(); return true;
}
bool Filter::removeSsid(const char* ssid) {
    for (size_t i = 0; i < _ssids.size(); i++) {
        if (_ssids[i].ssid.equals(ssid)) { _ssids.erase(_ssids.begin() + i); save(); return true; }
    }
    return false;
}
void Filter::clearSsids() { _ssids.clear(); save(); }

// ---------------------------------------------------------------------------
//  Persistence
// ---------------------------------------------------------------------------
bool Filter::save() {
    JsonDocument doc;
    doc["bpf"] = _expr;
    JsonArray m = doc["macs"].to<JsonArray>();
    for (auto& e : _macs) {
        char buf[18]; mac_to_str(e.mac, buf);
        JsonObject o = m.add<JsonObject>();
        o["mac"] = buf; o["note"] = e.note;
    }
    JsonArray ss = doc["ssids"].to<JsonArray>();
    for (auto& e : _ssids) {
        JsonObject o = ss.add<JsonObject>();
        o["ssid"] = e.ssid; o["exclude"] = e.exclude;
    }
    File f = LittleFS.open("/filters.json", "w");
    if (!f) return false;
    serializeJson(doc, f);
    f.close();
    return true;
}

bool Filter::load() {
    File f = LittleFS.open("/filters.json", "r");
    if (!f) return false;
    JsonDocument doc;
    DeserializationError err = deserializeJson(doc, f);
    f.close();
    if (err) return false;

    _macs.clear(); _ssids.clear();
    const char* bpf = doc["bpf"] | "";
    char e[64];
    setExpression(bpf, e, sizeof(e));
    for (JsonObject o : doc["macs"].as<JsonArray>()) {
        uint8_t mac[6];
        if (mac_from_str(o["mac"] | "", mac)) {
            MacFilterEntry me{}; memcpy(me.mac, mac, 6);
            strlcpy(me.note, o["note"] | "", sizeof(me.note));
            _macs.push_back(me);
        }
    }
    for (JsonObject o : doc["ssids"].as<JsonArray>()) {
        _ssids.push_back({String((const char*)(o["ssid"] | "")), (bool)(o["exclude"] | false)});
    }
    return true;
}
