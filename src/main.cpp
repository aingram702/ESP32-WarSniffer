// ============================================================================
//  main.cpp  —  ESP32-WarSniffer firmware entry point
//
//  Boot sequence:
//    1. Serial + status LED
//    2. LittleFS (web UI, OUI db, filters, pcap)
//    3. Settings (NVS) + capture filters
//    4. Capture subsystems (ring buffer, stats, detectors, pcap, sniffer)
//    5. SoftAP for out-of-band management + captive-portal DNS
//    6. Web interface (REST + WebSocket)
//
//  After boot, join Wi-Fi "WarSniffer" and open http://192.168.4.1
// ============================================================================
#include <Arduino.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include <DNSServer.h>
#include <LittleFS.h>

#include "config.h"
#include "settings.h"
#include "status_led.h"
#include "oui_lookup.h"
#include "ring_buffer.h"
#include "statistics.h"
#include "detector.h"
#include "filter.h"
#include "pcap_writer.h"
#include "sniffer.h"
#include "web_server.h"

static DNSServer dnsServer;
static uint32_t  lastSecondTick = 0;

static void startAccessPoint() {
    Settings& s = SettingsStore::instance().get();
    WiFi.persistent(false);
    WiFi.mode(WIFI_AP);
    WiFi.setHostname(HOSTNAME);

    IPAddress ip(AP_IP_ADDR), gw(AP_GATEWAY), sn(AP_SUBNET);
    WiFi.softAPConfig(ip, gw, sn);

    const char* pw = (strlen(s.ap_password) >= 8) ? s.ap_password : nullptr;  // open if too short
    bool ok = WiFi.softAP(s.ap_ssid, pw, s.ap_channel, s.ap_hidden, DEFAULT_AP_MAX_CONN);
    log_i("SoftAP '%s' %s ch%d -> %s", s.ap_ssid,
          ok ? "up" : "FAILED", s.ap_channel, WiFi.softAPIP().toString().c_str());
    if (!pw) log_w("AP is OPEN (no/short password) — set a WPA2 password!");

    // Captive portal: resolve every hostname to the device.
    dnsServer.setErrorReplyCode(DNSReplyCode::NoError);
    dnsServer.start(53, "*", WiFi.softAPIP());
}

void setup() {
    Serial.begin(SERIAL_BAUD);
    delay(200);
    Serial.println();
    Serial.println(F("=== ESP32-WarSniffer " WARSNIFFER_VERSION " ==="));

    StatusLed::instance().begin();

    if (!LittleFS.begin(true)) {
        log_e("LittleFS mount failed");
        StatusLed::instance().setState(LED_ERROR);
    }

    SettingsStore::instance().begin();
    OuiLookup::instance().begin();
    Filter::instance().begin();

    bool ok = true;
    ok &= RingBuffer::instance().begin();   // PSRAM pool
    Statistics::instance().begin();
    Detectors::instance().begin();
    PcapWriter::instance().begin();
    ok &= Sniffer::instance().begin();

    startAccessPoint();

    // Promiscuous needs the Wi-Fi driver running (AP already started it).
    esp_wifi_set_channel(SettingsStore::instance().get().ap_channel, WIFI_SECOND_CHAN_NONE);

    WebInterface::instance().begin();

    if (!ok) {
        StatusLed::instance().setState(LED_ERROR);
        log_e("Initialization incomplete — check PSRAM (need N16R8).");
    } else {
        StatusLed::instance().setState(LED_IDLE);
    }

    // Begin capturing immediately so the device is useful out of the box.
    Sniffer::instance().startCapture();
}

void loop() {
    dnsServer.processNextRequest();
    StatusLed::instance().tick();
    Sniffer::instance().serviceHop();
    WebInterface::instance().pump();

    uint32_t now = millis();
    static uint32_t lastAlertCount = 0;
    static uint32_t alertFlashUntil = 0;

    if (now - lastSecondTick >= 1000) {
        lastSecondTick = now;
        Statistics::instance().tickSecond();
        Detectors::instance().tick();

        // Flash the LED red for ~3 s whenever a new alert is raised.
        uint32_t ac = Detectors::instance().alertCount();
        if (ac > lastAlertCount) {
            lastAlertCount = ac;
            alertFlashUntil = now + 3000;
            StatusLed::instance().setState(LED_ALERT);
        }
    }
    // Return to the normal capturing/idle colour after the alert flash ends.
    if (alertFlashUntil && now > alertFlashUntil) {
        alertFlashUntil = 0;
        StatusLed::instance().setState(
            Sniffer::instance().isCapturing() ? LED_CAPTURING : LED_IDLE);
    }

    delay(2);  // yield to Wi-Fi / async tasks
}
