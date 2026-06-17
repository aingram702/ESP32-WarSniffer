// ============================================================================
//  frame_parser.cpp
//
//  All multi-byte reads are bounds-checked against `len` before dereferencing,
//  so a truncated or malformed frame can never read past the captured buffer.
// ============================================================================
#include "frame_parser.h"
#include "config.h"

namespace {

inline uint16_t rd16le(const uint8_t* p) { return (uint16_t)p[0] | ((uint16_t)p[1] << 8); }
inline uint16_t rd16be(const uint8_t* p) { return ((uint16_t)p[0] << 8) | p[1]; }

// EtherType constants
constexpr uint16_t ET_IPV4  = 0x0800;
constexpr uint16_t ET_ARP   = 0x0806;
constexpr uint16_t ET_IPV6  = 0x86DD;
constexpr uint16_t ET_EAPOL = 0x888E;

void classifyL3L4(const uint8_t* p, uint16_t avail, ParsedFrame& out);

}  // namespace

namespace FrameParser {

bool parse(const uint8_t* buf, uint16_t len, uint8_t channel, int8_t rssi,
           uint64_t timestamp_us, ParsedFrame& out) {
    memset(&out, 0, sizeof(out));
    out.timestamp_us = timestamp_us;
    out.rssi    = rssi;
    out.channel = channel;
    out.length  = len;

    if (len < 10) return false;  // need at least fc+dur+addr1

    uint16_t fc = rd16le(buf);
    out.type            = (fc >> 2) & 0x3;
    out.subtype         = (fc >> 4) & 0xF;
    out.to_ds           = fc & 0x0100;
    out.from_ds         = fc & 0x0200;
    out.protected_frame = fc & 0x4000;

    // addr1 always present at offset 4
    memcpy(out.addr1, buf + 4, 6);

    // Control frames may only have addr1 (e.g. ACK/CTS).
    if (len >= 16) { memcpy(out.addr2, buf + 10, 6); out.has_addr2 = true; }
    if (len >= 22) { memcpy(out.addr3, buf + 16, 6); out.has_addr3 = true; }

    // ---- Management frames: pull SSID from tagged parameters ----
    if (out.type == FRAME_TYPE_MGMT) {
        uint16_t bodyOff = 24;  // 3-addr mgmt header
        if (out.subtype == MGMT_BEACON || out.subtype == MGMT_PROBE_RESP ||
            out.subtype == MGMT_ASSOC_REQ || out.subtype == MGMT_REASSOC_REQ ||
            out.subtype == MGMT_PROBE_REQ) {
            // Beacon/ProbeResp/(Re)AssocResp have a 12/10-byte fixed field;
            // ProbeReq/AssocReq start tags right after header.
            uint16_t off = bodyOff;
            if (out.subtype == MGMT_BEACON || out.subtype == MGMT_PROBE_RESP) {
                if (bodyOff + 12 <= len) {
                    uint16_t cap = rd16le(buf + bodyOff + 10);
                    out.privacy = cap & 0x0010;   // capability "Privacy" bit
                }
                off += 12;  // timestamp(8)+interval(2)+capability(2)
            } else if (out.subtype == MGMT_ASSOC_REQ) {
                off += 4;   // capability(2)+listen interval(2)
            } else if (out.subtype == MGMT_REASSOC_REQ) {
                off += 10;  // cap(2)+listen(2)+current AP(6)
            }
            // Walk tagged params looking for SSID (tag 0).
            while (off + 2 <= len) {
                uint8_t tag = buf[off];
                uint8_t tlen = buf[off + 1];
                if (off + 2 + tlen > len) break;
                if (tag == 0) {  // SSID
                    uint8_t n = tlen < 32 ? tlen : 32;
                    // sanitize: keep printable, drop control bytes
                    uint8_t w = 0;
                    for (uint8_t i = 0; i < n; i++) {
                        uint8_t c = buf[off + 2 + i];
                        out.ssid[w++] = (c >= 0x20 && c < 0x7f) ? c : '.';
                    }
                    out.ssid[w] = '\0';
                    out.ssid_len = w;
                    break;
                }
                off += 2 + tlen;
            }
        }
        return true;
    }

    // ---- Data frames: decode L3/L4 if not encrypted ----
    if (out.type == FRAME_TYPE_DATA) {
        if (out.protected_frame) return true;  // can't see inside

        uint16_t hdr = 24;
        bool qos = (out.subtype & 0x08);                 // QoS data subtypes
        if (out.to_ds && out.from_ds) hdr += 6;          // addr4 (WDS)
        if (qos) hdr += 2;                               // QoS control
        // (HT control +4 would require order bit handling; skipped — rare)

        // Null-data subtypes carry no payload.
        bool nodata = (out.subtype == 0x04) || (out.subtype >= 0x04 && out.subtype <= 0x07 && !qos);
        if (nodata) return true;

        if (hdr + 8 > len) return true;                  // need LLC/SNAP
        const uint8_t* llc = buf + hdr;
        // LLC/SNAP: AA AA 03 00 00 00 <ethertype>
        if (llc[0] == 0xAA && llc[1] == 0xAA && llc[2] == 0x03) {
            uint16_t et = rd16be(llc + 6);
            const uint8_t* l3 = llc + 8;
            uint16_t avail = len - (hdr + 8);
            switch (et) {
                case ET_ARP:
                    out.l3 = L3_ARP;
                    // htype(2) ptype(2) hlen(1) plen(1) op(2) sha(6) spa(4) tha(6) tpa(4)
                    if (avail >= 28 && l3[4] == 6 && l3[5] == 4) {
                        out.arp_op = (uint8_t)rd16be(l3 + 6);
                        memcpy(out.arp_sender_mac, l3 + 8, 6);
                        memcpy(out.arp_sender_ip, l3 + 14, 4);
                        memcpy(out.arp_target_ip, l3 + 24, 4);
                    }
                    break;
                case ET_IPV6:  out.l3 = L3_IPV6; break;
                case ET_EAPOL:
                    out.l3 = L3_EAPOL;
                    out.is_eapol = true;
                    // PMKID heuristic: EAPOL-Key (type 3) M1 with RSN PMKID KDE.
                    if (avail >= 99 && l3[1] == 3) {
                        // scan key-data region for KDE: DD .. 00 0F AC 04 (PMKID)
                        for (uint16_t i = 95; i + 6 <= avail; i++) {
                            if (l3[i] == 0xDD && l3[i + 2] == 0x00 &&
                                l3[i + 3] == 0x0F && l3[i + 4] == 0xAC &&
                                l3[i + 5] == 0x04) {
                                out.has_pmkid = true;
                                break;
                            }
                        }
                    }
                    break;
                case ET_IPV4:
                    out.l3 = L3_IPV4;
                    classifyL3L4(l3, avail, out);
                    break;
                default:
                    out.l3 = L3_OTHER;
                    break;
            }
        }
        return true;
    }

    // control / extension frames: header-only metadata already set
    return true;
}

const char* typeName(uint8_t type) {
    switch (type) {
        case FRAME_TYPE_MGMT: return "Mgmt";
        case FRAME_TYPE_CTRL: return "Ctrl";
        case FRAME_TYPE_DATA: return "Data";
        default:              return "Ext";
    }
}

const char* subtypeName(uint8_t type, uint8_t subtype) {
    if (type == FRAME_TYPE_MGMT) {
        switch (subtype) {
            case MGMT_ASSOC_REQ:    return "Assoc Req";
            case MGMT_ASSOC_RESP:   return "Assoc Resp";
            case MGMT_REASSOC_REQ:  return "Reassoc Req";
            case MGMT_REASSOC_RESP: return "Reassoc Resp";
            case MGMT_PROBE_REQ:    return "Probe Req";
            case MGMT_PROBE_RESP:   return "Probe Resp";
            case MGMT_BEACON:       return "Beacon";
            case MGMT_DISASSOC:     return "Disassoc";
            case MGMT_AUTH:         return "Auth";
            case MGMT_DEAUTH:       return "Deauth";
            case MGMT_ACTION:       return "Action";
            default:                return "Mgmt";
        }
    }
    if (type == FRAME_TYPE_CTRL) {
        switch (subtype) {
            case 0x08: return "Block Ack Req";
            case 0x09: return "Block Ack";
            case 0x0A: return "PS-Poll";
            case 0x0B: return "RTS";
            case 0x0C: return "CTS";
            case 0x0D: return "ACK";
            case 0x0E: return "CF-End";
            default:   return "Ctrl";
        }
    }
    if (type == FRAME_TYPE_DATA) {
        if (subtype == 0x00) return "Data";
        if (subtype == 0x04) return "Null";
        if (subtype == 0x08) return "QoS Data";
        if (subtype == 0x0C) return "QoS Null";
        return "Data";
    }
    return "Ext";
}

}  // namespace FrameParser

namespace {

void classifyL3L4(const uint8_t* p, uint16_t avail, ParsedFrame& out) {
    if (avail < 20) return;
    uint8_t ihl = (p[0] & 0x0F) * 4;
    if (ihl < 20 || ihl > avail) return;
    uint8_t proto = p[9];
    const uint8_t* l4 = p + ihl;
    uint16_t l4avail = avail - ihl;

    switch (proto) {
        case 1:  out.l4 = L4_ICMP; return;
        case 6:  out.l4 = L4_TCP;  break;
        case 17: out.l4 = L4_UDP;  break;
        default: out.l4 = L4_OTHER; return;
    }
    if (l4avail < 4) return;
    out.src_port = rd16be(l4);
    out.dst_port = rd16be(l4 + 2);

    uint16_t sp = out.src_port, dp = out.dst_port;
    auto isPort = [&](uint16_t x) { return sp == x || dp == x; };
    if (isPort(53)) {
        out.app = APP_DNS;
        // DNS header: id(2) flags(2) qd(2) an(2) ns(2) ar(2)
        uint16_t l5avail = (l4avail >= 8) ? (l4avail - 8) : 0;  // UDP payload
        const uint8_t* dns = l4 + 8;
        if (out.l4 == L4_UDP && l5avail >= 8) {
            uint16_t flags = rd16be(dns + 2);
            out.dns_is_response = flags & 0x8000;
            out.dns_answers = rd16be(dns + 6);
        }
    }
    else if (isPort(67) || isPort(68)) out.app = APP_DHCP;
    else if (isPort(80))   out.app = APP_HTTP;
    else if (isPort(443))  out.app = APP_HTTPS;
    else if (isPort(5353)) out.app = APP_MDNS;
    else                   out.app = APP_OTHER;
}

}  // namespace
