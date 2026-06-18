// ============================================================================
//  credentials.h  —  Cleartext-credential harvesting
//
//  Passively extracts credentials that traverse the air *unencrypted* (open
//  networks, or any plaintext L7 protocol). Nothing here decrypts anything —
//  if the Wi-Fi or the application layer is encrypted (WPA2 data, HTTPS/TLS)
//  there is nothing to read and these functions simply find no matches.
//
//  Supported plaintext sources:
//    * HTTP  Basic auth  (Authorization: Basic <base64>)
//    * HTTP  login form bodies (user/pass field heuristics)
//    * FTP   USER / PASS              (port 21)
//    * POP3  USER / PASS              (port 110)
//    * IMAP  LOGIN <user> <pass>      (port 143)
//    * SMTP  AUTH PLAIN / LOGIN       (port 25 / 587)
//
//  Intended for authorized security testing of networks you own or are
//  permitted to assess.
// ============================================================================
#pragma once

#include <Arduino.h>
#include "types.h"
#include "config.h"

enum CredProto : uint8_t {
    CRED_HTTP_BASIC = 0,
    CRED_HTTP_FORM,
    CRED_FTP,
    CRED_POP3,
    CRED_IMAP,
    CRED_SMTP,
    CRED_TELNET,
};

struct Credential {
    uint32_t id;
    uint64_t timestamp_us;
    uint8_t  proto;            // CredProto
    uint8_t  channel;
    uint8_t  src_ip[4];
    uint8_t  dst_ip[4];
    uint16_t dst_port;
    char     username[64];
    char     password[64];
    char     context[64];      // host / URL / note
};

class CredentialHarvester {
public:
    static CredentialHarvester& instance();
    void begin();

    // Inspect a parsed frame + its raw captured bytes. No-op unless the frame
    // carries readable L7 payload and harvesting is enabled.
    void inspect(const ParsedFrame& f, const uint8_t* frame, uint16_t frameLen);

    uint32_t total() const { return _total; }
    uint16_t recent(Credential* out, uint16_t max, uint32_t sinceId);
    void     clear();

private:
    CredentialHarvester() {}

    void add(const ParsedFrame& f, uint8_t proto,
             const char* user, const char* pass, const char* ctx);

    // protocol scanners (payload is a bounded, non-NUL-terminated buffer)
    void scanHttp(const ParsedFrame& f, const char* p, uint16_t n);
    void scanLineProto(const ParsedFrame& f, const char* p, uint16_t n);  // ftp/pop3/imap/smtp

    // pending USER/AUTH state keyed by (src_ip,dst_ip,dst_port)
    struct Pending {
        bool     used;
        uint8_t  src_ip[4], dst_ip[4];
        uint16_t dst_port;
        uint8_t  proto;
        char     username[64];
        uint8_t  smtp_stage;   // SMTP AUTH LOGIN: 0 none,1 expect user,2 expect pass
        uint32_t last_ms;
    };
    Pending* findPending(const ParsedFrame& f, bool create);

    Credential _ring[CRED_MAX_ENTRIES]{};
    Pending    _pending[CRED_MAX_PENDING]{};
    uint32_t   _head = 0;
    uint32_t   _total = 0;
    SemaphoreHandle_t _mtx = nullptr;
};
