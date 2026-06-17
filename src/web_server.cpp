// ============================================================================
//  web_server.cpp  —  REST API + WebSocket, serving the WarSniffer UI
//
//  Security notes:
//   * Out-of-band management runs on a WPA2-protected SoftAP (see settings).
//   * All string inputs are length-bounded (strlcpy) and numeric inputs are
//     range-checked. JSON bodies are capped.
//   * PCAP downloads are restricted to the /pcap directory with a strict
//     filename whitelist (no path traversal).
//   * Conservative security response headers are added to every response.
// ============================================================================
#include "web_server.h"
#include "config.h"
#include "settings.h"
#include "statistics.h"
#include "detector.h"
#include "filter.h"
#include "ring_buffer.h"
#include "pcap_writer.h"
#include "sniffer.h"
#include "frame_parser.h"

#include <ESPAsyncWebServer.h>
#include <AsyncJson.h>
#include <ArduinoJson.h>
#include <LittleFS.h>
#include <esp_timer.h>
#include <esp_system.h>
#include <esp_heap_caps.h>

WebInterface& WebInterface::instance() { static WebInterface w; return w; }

// ---------------------------------------------------------------------------
//  Small helpers
// ---------------------------------------------------------------------------
static void addSecurityHeaders(AsyncWebServerResponse* r) {
    r->addHeader("X-Content-Type-Options", "nosniff");
    r->addHeader("X-Frame-Options", "DENY");
    r->addHeader("Referrer-Policy", "no-referrer");
    r->addHeader("Content-Security-Policy",
                 "default-src 'self'; img-src 'self' data:; "
                 "style-src 'self' 'unsafe-inline'; script-src 'self'; "
                 "connect-src 'self' ws:; frame-ancestors 'none'");
}

static void sendJson(AsyncWebServerRequest* req, int code, JsonDocument& doc) {
    AsyncResponseStream* res = req->beginResponseStream("application/json");
    res->setCode(code);
    addSecurityHeaders(res);
    serializeJson(doc, *res);
    req->send(res);
}

static void sendMsg(AsyncWebServerRequest* req, int code, const char* msg) {
    JsonDocument d; d["ok"] = (code < 400); d["message"] = msg;
    sendJson(req, code, d);
}

// Fill a JSON object describing one captured frame (summary row).
static void frameToJson(const RingSlot& s, JsonObject o) {
    const ParsedFrame& f = s.meta;
    char a1[18], a2[18], a3[18];
    o["id"]   = s.id;
    o["ts"]   = (double)f.timestamp_us / 1000000.0;
    o["ch"]   = f.channel;
    o["rssi"] = f.rssi;
    o["len"]  = f.length;
    o["type"] = FrameParser::typeName(f.type);
    o["sub"]  = FrameParser::subtypeName(f.type, f.subtype);
    o["enc"]  = f.protected_frame;
    o["dst"]  = mac_to_str(f.addr1, a1);
    if (f.has_addr2) o["src"]   = mac_to_str(f.addr2, a2);
    if (f.has_addr3) o["bssid"] = mac_to_str(f.addr3, a3);

    const char* proto = "";
    if (f.is_eapol)            proto = f.has_pmkid ? "EAPOL/PMKID" : "EAPOL";
    else if (f.l3 == L3_ARP)   proto = "ARP";
    else if (f.app == APP_DNS) proto = "DNS";
    else if (f.app == APP_DHCP)proto = "DHCP";
    else if (f.app == APP_HTTP)proto = "HTTP";
    else if (f.app == APP_HTTPS)proto = "TLS";
    else if (f.app == APP_MDNS)proto = "mDNS";
    else if (f.l3 == L3_IPV4)  proto = "IPv4";
    else if (f.l3 == L3_IPV6)  proto = "IPv6";
    o["proto"] = proto;

    char info[64] = "";
    if (f.type == FRAME_TYPE_MGMT && f.ssid_len) snprintf(info, sizeof(info), "SSID=%s", f.ssid);
    else if (f.src_port || f.dst_port) snprintf(info, sizeof(info), "%u→%u", f.src_port, f.dst_port);
    o["info"] = info;
}

// ---------------------------------------------------------------------------
//  Lifecycle
// ---------------------------------------------------------------------------
void WebInterface::begin() {
    _server = new AsyncWebServer(80);
    _ws = new AsyncWebSocket("/ws");
    _ws->onEvent([this](AsyncWebSocket* s, AsyncWebSocketClient* c, AwsEventType t,
                        void* arg, uint8_t* d, size_t l) {
        onWsEvent(s, c, t, arg, d, l);
    });
    _server->addHandler(_ws);
    routes();
    _server->begin();
    log_i("Web interface up on :80");
}

void WebInterface::onWsEvent(AsyncWebSocket*, AsyncWebSocketClient* client,
                             uint8_t type, void*, uint8_t*, size_t) {
    if (type == WS_EVT_CONNECT) {
        Sniffer::instance().setClientConnected(true);
        log_i("WS client %u connected", client->id());
    } else if (type == WS_EVT_DISCONNECT) {
        if (_ws->count() == 0) Sniffer::instance().setClientConnected(false);
    }
}

uint32_t WebInterface::clientCount() const { return _ws ? _ws->count() : 0; }

// ---------------------------------------------------------------------------
//  Routes
// ---------------------------------------------------------------------------
void WebInterface::routes() {
    AsyncWebServer& srv = *_server;

    // ---- status ----
    srv.on("/api/status", HTTP_GET, [](AsyncWebServerRequest* req) {
        Settings& s = SettingsStore::instance().get();
        JsonDocument d;
        d["version"]   = WARSNIFFER_VERSION;
        d["build"]     = WARSNIFFER_BUILD;
        d["uptime_s"]  = (uint32_t)(esp_timer_get_time() / 1000000ULL);
        d["capturing"] = Sniffer::instance().isCapturing();
        d["channel"]   = Sniffer::instance().currentChannel();
        d["hopping"]   = s.channel_hop;
        d["heap_free"] = (uint32_t)esp_get_free_heap_size();
        d["psram_free"]= (uint32_t)heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
        d["ap_ssid"]   = s.ap_ssid;
        d["default_password"] = SettingsStore::instance().usingDefaultPassword();
        d["frames_total"] = RingBuffer::instance().totalCaptured();
        d["frames_stored"]= RingBuffer::instance().stored();
        d["dropped"]   = Statistics::instance().global().dropped;
        d["ap_count"]  = Statistics::instance().apCount();
        d["sta_count"] = Statistics::instance().staCount();
        d["alert_count"] = Detectors::instance().alertCount();
        d["pcap_open"] = PcapWriter::instance().isOpen();
        d["pcap_bytes"]= PcapWriter::instance().bytesWritten();
        d["clients"]   = WebInterface::instance().clientCount();
        sendJson(req, 200, d);
    });

    // ---- statistics ----
    srv.on("/api/stats", HTTP_GET, [](AsyncWebServerRequest* req) {
        const GlobalStats& g = Statistics::instance().global();
        JsonDocument d;
        d["frames"] = g.frames_total; d["bytes"] = g.bytes_total;
        d["mgmt"] = g.mgmt; d["ctrl"] = g.ctrl; d["data"] = g.data;
        d["arp"] = g.arp; d["dns"] = g.dns; d["dhcp"] = g.dhcp;
        d["http"] = g.http; d["https"] = g.https; d["eapol"] = g.eapol;
        d["ipv4"] = g.ipv4; d["ipv6"] = g.ipv6; d["encrypted"] = g.encrypted;
        d["dropped"] = g.dropped;
        JsonArray ch = d["per_channel"].to<JsonArray>();
        for (int i = 1; i <= MAX_CHANNELS; i++) ch.add(g.per_channel[i]);
        JsonArray pps = d["pps"].to<JsonArray>();
        for (int i = 0; i < 60; i++) {
            uint8_t idx = (g.pps_head + i) % 60;
            pps.add(g.pps_history[idx]);
        }
        sendJson(req, 200, d);
    });

    // ---- devices (AP + station inventory) ----
    srv.on("/api/devices", HTTP_GET, [](AsyncWebServerRequest* req) {
        JsonDocument d;
        uint32_t now = millis();
        JsonArray aps = d["aps"].to<JsonArray>();
        Statistics& st = Statistics::instance();
        uint16_t n = st.apCount();
        for (uint16_t i = 0; i < n; i++) {
            ApInfo a; if (!st.apAt(i, a)) continue;
            char m[18]; JsonObject o = aps.add<JsonObject>();
            o["bssid"] = mac_to_str(a.bssid, m);
            o["ssid"] = a.ssid; o["channel"] = a.channel;
            o["rssi"] = a.rssi; o["rssi_min"] = a.rssi_min; o["rssi_max"] = a.rssi_max;
            o["privacy"] = a.privacy; o["beacons"] = a.beacons;
            o["vendor"] = a.vendor; o["age_s"] = (now - a.last_seen_ms) / 1000;
        }
        JsonArray stas = d["stas"].to<JsonArray>();
        uint16_t sn = st.staCount();
        for (uint16_t i = 0; i < sn; i++) {
            StaInfo s; if (!st.staAt(i, s)) continue;
            char m[18], b[18]; JsonObject o = stas.add<JsonObject>();
            o["mac"] = mac_to_str(s.mac, m);
            o["rssi"] = s.rssi; o["frames"] = s.frames;
            o["randomized"] = s.randomized; o["vendor"] = s.vendor;
            o["associated"] = s.associated;
            if (s.associated) o["bssid"] = mac_to_str(s.bssid, b);
            o["last_probe"] = s.last_probe;
            o["age_s"] = (now - s.last_seen_ms) / 1000;
        }
        sendJson(req, 200, d);
    });

    // ---- alerts ----
    srv.on("/api/alerts", HTTP_GET, [](AsyncWebServerRequest* req) {
        uint32_t since = 0;
        if (req->hasParam("since")) since = req->getParam("since")->value().toInt();
        static const char* TYPES[] = {"none","deauth_flood","evil_twin","pmkid",
                                      "arp_spoof","dns_anomaly","beacon_flood","karma"};
        static const char* SEV[] = {"info","warning","critical"};
        Alert buf[16];
        uint16_t n = Detectors::instance().recentAlerts(buf, 16, since);
        JsonDocument d;
        JsonArray arr = d["alerts"].to<JsonArray>();
        for (uint16_t i = 0; i < n; i++) {
            char b[18], s[18]; JsonObject o = arr.add<JsonObject>();
            o["id"] = buf[i].id;
            o["ts"] = (double)buf[i].timestamp_us / 1000000.0;
            o["type"] = TYPES[buf[i].type <= 7 ? buf[i].type : 0];
            o["severity"] = SEV[buf[i].severity <= 2 ? buf[i].severity : 0];
            o["channel"] = buf[i].channel;
            o["detail"] = buf[i].detail;
            if (!mac_is_zero(buf[i].bssid))   o["bssid"] = mac_to_str(buf[i].bssid, b);
            if (!mac_is_zero(buf[i].station)) o["station"] = mac_to_str(buf[i].station, s);
        }
        sendJson(req, 200, d);
    });
    srv.on("/api/alerts/clear", HTTP_POST, [](AsyncWebServerRequest* req) {
        Detectors::instance().clearAlerts();
        sendMsg(req, 200, "cleared");
    });

    // ---- single frame detail (hex + decode) ----
    srv.on("/api/frame", HTTP_GET, [](AsyncWebServerRequest* req) {
        if (!req->hasParam("id")) { sendMsg(req, 400, "id required"); return; }
        uint64_t id = strtoull(req->getParam("id")->value().c_str(), nullptr, 10);
        uint8_t tmp[MAX_SNAP_LEN];
        RingSlot slot;
        if (!RingBuffer::instance().getById(id, slot, tmp, sizeof(tmp))) {
            sendMsg(req, 404, "frame not found (evicted?)"); return;
        }
        JsonDocument d;
        JsonObject meta = d["meta"].to<JsonObject>();
        frameToJson(slot, meta);
        // hex dump
        String hex; hex.reserve(slot.cap_len * 2);
        const char* H = "0123456789abcdef";
        for (uint16_t i = 0; i < slot.cap_len; i++) {
            hex += H[tmp[i] >> 4]; hex += H[tmp[i] & 0xF];
        }
        d["hex"] = hex;
        d["cap_len"] = slot.cap_len;
        sendJson(req, 200, d);
    });

    // ---- capture control ----
    srv.on("/api/capture/start", HTTP_POST, [](AsyncWebServerRequest* req) {
        Sniffer::instance().startCapture();
        sendMsg(req, 200, "capture started");
    });
    srv.on("/api/capture/stop", HTTP_POST, [](AsyncWebServerRequest* req) {
        Sniffer::instance().stopCapture();
        sendMsg(req, 200, "capture stopped");
    });
    srv.on("/api/capture/clear", HTTP_POST, [](AsyncWebServerRequest* req) {
        RingBuffer::instance().clear();
        Statistics::instance().reset();
        sendMsg(req, 200, "buffers cleared");
    });

    // ---- settings ----
    srv.on("/api/settings", HTTP_GET, [](AsyncWebServerRequest* req) {
        Settings& s = SettingsStore::instance().get();
        JsonDocument d;
        d["ap_ssid"] = s.ap_ssid;
        d["ap_channel"] = s.ap_channel; d["ap_hidden"] = s.ap_hidden;
        d["channel_hop"] = s.channel_hop;
        d["hop_pause_on_client"] = s.hop_pause_on_client;
        d["hop_interval_ms"] = s.hop_interval_ms;
        d["fixed_channel"] = s.fixed_channel;
        d["snap_len"] = s.snap_len; d["ws_max_pps"] = s.ws_max_pps;
        d["cap_mgmt"] = s.cap_mgmt; d["cap_ctrl"] = s.cap_ctrl; d["cap_data"] = s.cap_data;
        d["filter_enabled"] = s.filter_enabled;
        d["mac_filter_is_whitelist"] = s.mac_filter_is_whitelist;
        d["pcap_enabled"] = s.pcap_enabled; d["pcap_radiotap"] = s.pcap_radiotap;
        d["pcap_max_bytes"] = s.pcap_max_bytes;
        d["det_deauth"] = s.det_deauth; d["det_evil_twin"] = s.det_evil_twin;
        d["det_pmkid"] = s.det_pmkid; d["det_arp_spoof"] = s.det_arp_spoof;
        d["det_dns_anomaly"] = s.det_dns_anomaly; d["det_beacon_flood"] = s.det_beacon_flood;
        d["det_deauth_threshold"] = s.det_deauth_threshold;
        d["det_beacon_threshold"] = s.det_beacon_threshold;
        d["geo_enabled"] = s.geo_enabled; d["geo_lat"] = s.geo_lat;
        d["geo_lon"] = s.geo_lon; d["geo_label"] = s.geo_label;
        JsonArray ce = d["channel_enabled"].to<JsonArray>();
        for (int i = 1; i <= MAX_CHANNELS; i++) ce.add(s.channel_enabled[i]);
        sendJson(req, 200, d);
    });

    auto* settingsHandler = new AsyncCallbackJsonWebHandler("/api/settings",
        [](AsyncWebServerRequest* req, JsonVariant& json) {
            JsonObject b = json.as<JsonObject>();
            Settings& s = SettingsStore::instance().get();
            bool apChanged = false;

            if (b["ap_ssid"].is<const char*>()) {
                const char* v = b["ap_ssid"];
                if (strlen(v) >= 1 && strlen(v) <= 32) { strlcpy(s.ap_ssid, v, sizeof(s.ap_ssid)); apChanged = true; }
            }
            if (b["ap_password"].is<const char*>()) {
                const char* v = b["ap_password"];
                size_t L = strlen(v);
                if (L == 0 || (L >= 8 && L <= 63)) { strlcpy(s.ap_password, v, sizeof(s.ap_password)); apChanged = true; }
                else { sendMsg(req, 400, "AP password must be empty or 8-63 chars"); return; }
            }
            if (b["ap_channel"].is<int>()) { int c = b["ap_channel"]; if (c>=1&&c<=13){ s.ap_channel=c; apChanged=true; } }
            if (b["ap_hidden"].is<bool>()) { s.ap_hidden = b["ap_hidden"]; apChanged = true; }

            if (b["channel_hop"].is<bool>())  s.channel_hop = b["channel_hop"];
            if (b["hop_pause_on_client"].is<bool>()) s.hop_pause_on_client = b["hop_pause_on_client"];
            if (b["hop_interval_ms"].is<int>()) { int v=b["hop_interval_ms"]; s.hop_interval_ms = constrain(v,50,5000); }
            if (b["fixed_channel"].is<int>()) { int v=b["fixed_channel"]; if(v>=1&&v<=14) s.fixed_channel=v; }
            if (b["snap_len"].is<int>()) { int v=b["snap_len"]; s.snap_len = constrain(v,64,MAX_SNAP_LEN); }
            if (b["ws_max_pps"].is<int>()) { int v=b["ws_max_pps"]; s.ws_max_pps = constrain(v,1,200); }
            if (b["cap_mgmt"].is<bool>()) s.cap_mgmt = b["cap_mgmt"];
            if (b["cap_ctrl"].is<bool>()) s.cap_ctrl = b["cap_ctrl"];
            if (b["cap_data"].is<bool>()) s.cap_data = b["cap_data"];
            if (b["filter_enabled"].is<bool>()) s.filter_enabled = b["filter_enabled"];
            if (b["mac_filter_is_whitelist"].is<bool>()) s.mac_filter_is_whitelist = b["mac_filter_is_whitelist"];
            if (b["pcap_enabled"].is<bool>()) s.pcap_enabled = b["pcap_enabled"];
            if (b["pcap_radiotap"].is<bool>()) s.pcap_radiotap = b["pcap_radiotap"];
            if (b["pcap_max_bytes"].is<uint32_t>()) { uint32_t v=b["pcap_max_bytes"]; s.pcap_max_bytes = constrain((long)v, 65536L, 8388608L); }
            if (b["det_deauth"].is<bool>()) s.det_deauth = b["det_deauth"];
            if (b["det_evil_twin"].is<bool>()) s.det_evil_twin = b["det_evil_twin"];
            if (b["det_pmkid"].is<bool>()) s.det_pmkid = b["det_pmkid"];
            if (b["det_arp_spoof"].is<bool>()) s.det_arp_spoof = b["det_arp_spoof"];
            if (b["det_dns_anomaly"].is<bool>()) s.det_dns_anomaly = b["det_dns_anomaly"];
            if (b["det_beacon_flood"].is<bool>()) s.det_beacon_flood = b["det_beacon_flood"];
            if (b["det_deauth_threshold"].is<int>()) { int v=b["det_deauth_threshold"]; s.det_deauth_threshold=constrain(v,2,1000); }
            if (b["det_beacon_threshold"].is<int>()) { int v=b["det_beacon_threshold"]; s.det_beacon_threshold=constrain(v,5,1000); }
            if (b["geo_enabled"].is<bool>()) s.geo_enabled = b["geo_enabled"];
            if (b["geo_lat"].is<double>()) s.geo_lat = b["geo_lat"];
            if (b["geo_lon"].is<double>()) s.geo_lon = b["geo_lon"];
            if (b["geo_label"].is<const char*>()) strlcpy(s.geo_label, b["geo_label"], sizeof(s.geo_label));
            if (b["channel_enabled"].is<JsonArray>()) {
                int i = 1;
                for (JsonVariant v : b["channel_enabled"].as<JsonArray>()) {
                    if (i > MAX_CHANNELS) break;
                    s.channel_enabled[i++] = v.as<bool>();
                }
            }
            SettingsStore::instance().save();
            Sniffer::instance().applyChannelConfig();
            JsonDocument d; d["ok"] = true; d["ap_changed"] = apChanged;
            d["message"] = apChanged ? "saved (AP change applies after reboot)" : "saved";
            sendJson(req, 200, d);
        });
    settingsHandler->setMaxContentLength(4096);
    srv.addHandler(settingsHandler);

    // ---- filters ----
    srv.on("/api/filters", HTTP_GET, [](AsyncWebServerRequest* req) {
        Filter& fl = Filter::instance();
        JsonDocument d;
        d["bpf"] = fl.expression();
        JsonArray m = d["macs"].to<JsonArray>();
        for (auto& e : fl.macList()) { char b[18]; JsonObject o=m.add<JsonObject>(); o["mac"]=mac_to_str(e.mac,b); o["note"]=e.note; }
        JsonArray ss = d["ssids"].to<JsonArray>();
        for (auto& e : fl.ssidList()) { JsonObject o=ss.add<JsonObject>(); o["ssid"]=e.ssid; o["exclude"]=e.exclude; }
        sendJson(req, 200, d);
    });
    auto* bpfHandler = new AsyncCallbackJsonWebHandler("/api/filters/bpf",
        [](AsyncWebServerRequest* req, JsonVariant& json) {
            const char* expr = json["bpf"] | "";
            char err[64];
            if (Filter::instance().setExpression(expr, err, sizeof(err))) {
                Filter::instance().save();
                sendMsg(req, 200, "filter compiled");
            } else {
                JsonDocument d; d["ok"]=false; d["message"]="parse error"; d["error"]=err;
                sendJson(req, 400, d);
            }
        });
    bpfHandler->setMaxContentLength(512);
    srv.addHandler(bpfHandler);

    auto* macHandler = new AsyncCallbackJsonWebHandler("/api/filters/mac",
        [](AsyncWebServerRequest* req, JsonVariant& json) {
            const char* macStr = json["mac"] | "";
            bool remove = json["remove"] | false;
            uint8_t mac[6];
            if (!mac_from_str(macStr, mac)) { sendMsg(req, 400, "invalid MAC"); return; }
            bool ok = remove ? Filter::instance().removeMac(mac)
                             : Filter::instance().addMac(mac, json["note"] | "");
            sendMsg(req, ok ? 200 : 400, ok ? "ok" : "list full or duplicate");
        });
    macHandler->setMaxContentLength(256);
    srv.addHandler(macHandler);

    auto* ssidHandler = new AsyncCallbackJsonWebHandler("/api/filters/ssid",
        [](AsyncWebServerRequest* req, JsonVariant& json) {
            const char* ssid = json["ssid"] | "";
            bool remove = json["remove"] | false;
            bool exclude = json["exclude"] | false;
            if (!*ssid) { sendMsg(req, 400, "ssid required"); return; }
            bool ok = remove ? Filter::instance().removeSsid(ssid)
                             : Filter::instance().addSsid(ssid, exclude);
            sendMsg(req, ok ? 200 : 400, ok ? "ok" : "list full");
        });
    ssidHandler->setMaxContentLength(256);
    srv.addHandler(ssidHandler);

    // ---- time sync (browser -> device epoch) ----
    auto* timeHandler = new AsyncCallbackJsonWebHandler("/api/time",
        [](AsyncWebServerRequest* req, JsonVariant& json) {
            uint64_t epoch = json["epoch"].as<uint64_t>();
            if (epoch > 1600000000ULL) {
                PcapWriter::instance().setEpochBase(epoch, esp_timer_get_time());
                sendMsg(req, 200, "time synced");
            } else sendMsg(req, 400, "bad epoch");
        });
    timeHandler->setMaxContentLength(128);
    srv.addHandler(timeHandler);

    // ---- PCAP files ----
    srv.on("/api/pcap/list", HTTP_GET, [](AsyncWebServerRequest* req) {
        JsonDocument d;
        JsonArray arr = d["files"].to<JsonArray>();
        File dir = LittleFS.open(PCAP_DIR);
        if (dir) {
            File f = dir.openNextFile();
            while (f) {
                JsonObject o = arr.add<JsonObject>();
                o["name"] = String(f.name());
                o["size"] = (uint32_t)f.size();
                f = dir.openNextFile();
            }
        }
        d["active"] = PcapWriter::instance().isOpen();
        sendJson(req, 200, d);
    });
    srv.on("/api/pcap/download", HTTP_GET, [](AsyncWebServerRequest* req) {
        if (!req->hasParam("file")) { sendMsg(req, 400, "file required"); return; }
        String name = req->getParam("file")->value();
        // strict whitelist: cap-<digits>.pcap, no path separators
        if (name.indexOf('/') >= 0 || name.indexOf("..") >= 0 ||
            !name.startsWith("cap-") || !name.endsWith(".pcap")) {
            sendMsg(req, 400, "invalid filename"); return;
        }
        String path = String(PCAP_DIR) + "/" + name;
        if (!LittleFS.exists(path)) { sendMsg(req, 404, "not found"); return; }
        AsyncWebServerResponse* res = req->beginResponse(LittleFS, path, "application/vnd.tcpdump.pcap", true);
        addSecurityHeaders(res);
        req->send(res);
    });
    auto* pcapDel = new AsyncCallbackJsonWebHandler("/api/pcap/delete",
        [](AsyncWebServerRequest* req, JsonVariant& json) {
            String name = json["file"] | "";
            if (name.indexOf('/') >= 0 || name.indexOf("..") >= 0 ||
                !name.startsWith("cap-") || !name.endsWith(".pcap")) {
                sendMsg(req, 400, "invalid filename"); return;
            }
            String path = String(PCAP_DIR) + "/" + name;
            bool ok = LittleFS.remove(path);
            sendMsg(req, ok ? 200 : 404, ok ? "deleted" : "not found");
        });
    pcapDel->setMaxContentLength(256);
    srv.addHandler(pcapDel);

    // ---- system ----
    srv.on("/api/factory-reset", HTTP_POST, [](AsyncWebServerRequest* req) {
        SettingsStore::instance().factoryReset();
        sendMsg(req, 200, "factory reset; rebooting");
        req->onDisconnect([]() { delay(200); ESP.restart(); });
    });
    srv.on("/api/reboot", HTTP_POST, [](AsyncWebServerRequest* req) {
        sendMsg(req, 200, "rebooting");
        req->onDisconnect([]() { delay(200); ESP.restart(); });
    });

    // ---- static UI from LittleFS ----
    srv.serveStatic("/", LittleFS, "/www/").setDefaultFile("index.html");

    // SPA / captive-portal fallback -> serve index.html
    srv.onNotFound([](AsyncWebServerRequest* req) {
        if (req->method() == HTTP_GET && LittleFS.exists("/www/index.html")) {
            AsyncWebServerResponse* res = req->beginResponse(LittleFS, "/www/index.html", "text/html");
            addSecurityHeaders(res);
            req->send(res);
        } else {
            sendMsg(req, 404, "not found");
        }
    });
}

// ---------------------------------------------------------------------------
//  WebSocket pump  (called from main loop)
// ---------------------------------------------------------------------------
void WebInterface::pump() {
    if (!_ws || _ws->count() == 0) return;
    Settings& s = SettingsStore::instance().get();
    uint32_t now = millis();

    // ---- live frames (batched) ----
    uint32_t frameInterval = 1000 / (s.ws_max_pps > 0 ? s.ws_max_pps : 1);
    if (frameInterval < 100) frameInterval = 100;   // batch at most ~10 Hz
    if (now - _lastFramePushMs >= frameInterval && _ws->availableForWriteAll()) {
        _lastFramePushMs = now;
        JsonDocument d;
        d["t"] = "frames";
        JsonArray arr = d["f"].to<JsonArray>();
        uint32_t batch = s.ws_max_pps > 0 ? s.ws_max_pps : 20;
        if (batch > 40) batch = 40;
        _frameCursor = RingBuffer::instance().forEachSince(_frameCursor, batch,
            [&](const RingSlot& slot) { frameToJson(slot, arr.add<JsonObject>()); });
        if (arr.size() > 0) {
            String out; serializeJson(d, out);
            _ws->textAll(out);
        }
    }

    // ---- stats + alerts (1 Hz) ----
    if (now - _lastStatsPushMs >= 1000 && _ws->availableForWriteAll()) {
        _lastStatsPushMs = now;
        const GlobalStats& g = Statistics::instance().global();
        JsonDocument d;
        d["t"] = "stat";
        d["frames"] = g.frames_total; d["dropped"] = g.dropped;
        d["pps"] = g.pps_history[(g.pps_head + 59) % 60];
        d["ap"] = Statistics::instance().apCount();
        d["sta"] = Statistics::instance().staCount();
        d["ch"] = Sniffer::instance().currentChannel();
        d["alerts"] = Detectors::instance().alertCount();
        Alert la;
        if (Detectors::instance().alertCount() > _alertCursor && Detectors::instance().lastAlert(la)) {
            _alertCursor = la.id;
            JsonObject a = d["alert"].to<JsonObject>();
            static const char* TYPES[] = {"none","deauth_flood","evil_twin","pmkid",
                                          "arp_spoof","dns_anomaly","beacon_flood","karma"};
            static const char* SEV[] = {"info","warning","critical"};
            a["id"] = la.id;
            a["type"] = TYPES[la.type <= 7 ? la.type : 0];
            a["severity"] = SEV[la.severity <= 2 ? la.severity : 0];
            a["detail"] = la.detail; a["channel"] = la.channel;
        }
        String out; serializeJson(d, out);
        _ws->textAll(out);
        _ws->cleanupClients();
    }
}
