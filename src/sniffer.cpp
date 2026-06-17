// ============================================================================
//  sniffer.cpp
// ============================================================================
#include "sniffer.h"
#include "settings.h"
#include "types.h"
#include "frame_parser.h"
#include "filter.h"
#include "ring_buffer.h"
#include "statistics.h"
#include "detector.h"
#include "pcap_writer.h"
#include "status_led.h"

#include <esp_wifi.h>
#include <esp_timer.h>
#include <esp_heap_caps.h>

#define POOL_N 128

namespace {
struct RawCap {
    uint16_t len;
    int8_t   rssi;
    uint8_t  channel;
    uint64_t ts;
    uint8_t  data[MAX_SNAP_LEN];
};
}

Sniffer& Sniffer::instance() { static Sniffer s; return s; }

bool Sniffer::begin() {
    size_t poolBytes = (size_t)POOL_N * sizeof(RawCap);
    _pool = heap_caps_malloc(poolBytes, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!_pool) _pool = malloc(poolBytes);
    if (!_pool) { log_e("Sniffer: pool alloc failed"); return false; }

    _freeq = xQueueCreate(POOL_N, sizeof(uint16_t));
    _workq = xQueueCreate(POOL_N, sizeof(uint16_t));
    if (!_freeq || !_workq) { log_e("Sniffer: queue alloc failed"); return false; }
    for (uint16_t i = 0; i < POOL_N; i++) xQueueSend(_freeq, &i, 0);

    // Pin the capture task to core 1 (Wi-Fi/LWIP run on core 0).
    xTaskCreatePinnedToCore(captureTask, "wsniff_cap", 6144, this, 3, &_task, 1);
    return true;
}

void Sniffer::setChannel(uint8_t ch) {
    if (ch < CHANNEL_MIN || ch > CHANNEL_MAX) return;
    esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
    _channel = ch;
}

void Sniffer::applyChannelConfig() {
    Settings& s = SettingsStore::instance().get();
    if (!s.channel_hop) setChannel(s.fixed_channel);
}

void Sniffer::startCapture() {
    if (_capturing) return;
    // Filter packet types: capture mgmt+data+ctrl per esp_wifi mask.
    wifi_promiscuous_filter_t filt = {};
    filt.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT |
                       WIFI_PROMIS_FILTER_MASK_DATA |
                       WIFI_PROMIS_FILTER_MASK_CTRL;
    esp_wifi_set_promiscuous_filter(&filt);
    esp_wifi_set_promiscuous_rx_cb(&Sniffer::promiscuousCb);
    esp_wifi_set_promiscuous(true);

    Settings& s = SettingsStore::instance().get();
    if (!s.channel_hop) setChannel(s.fixed_channel);
    if (s.pcap_enabled) PcapWriter::instance().start();

    _capturing = true;
    StatusLed::instance().setState(LED_CAPTURING);
    log_i("Capture started (hop=%d)", s.channel_hop);
}

void Sniffer::stopCapture() {
    if (!_capturing) return;
    _capturing = false;
    esp_wifi_set_promiscuous(false);
    PcapWriter::instance().stop();
    StatusLed::instance().setState(LED_IDLE);
    log_i("Capture stopped");
}

// ---- promiscuous RX callback (runs in the Wi-Fi task context) -------------
void Sniffer::promiscuousCb(void* buf, wifi_promiscuous_pkt_type_t type) {
    Sniffer& self = Sniffer::instance();
    if (!self._capturing || !buf) return;

    const wifi_promiscuous_pkt_t* pkt = (const wifi_promiscuous_pkt_t*)buf;
    uint16_t len = pkt->rx_ctrl.sig_len;
    if (len < 10) return;

    uint16_t snap = SettingsStore::instance().get().snap_len;
    if (snap > MAX_SNAP_LEN) snap = MAX_SNAP_LEN;
    uint16_t cap = len < snap ? len : snap;

    uint16_t idx;
    if (xQueueReceive(self._freeq, &idx, 0) != pdTRUE) {
        Statistics::instance().noteDropped();   // pool exhausted -> drop
        return;
    }
    RawCap* slot = &((RawCap*)self._pool)[idx];
    slot->len     = len;                          // original on-air length
    slot->rssi    = pkt->rx_ctrl.rssi;
    slot->channel = pkt->rx_ctrl.channel;
    slot->ts      = esp_timer_get_time();
    memcpy(slot->data, pkt->payload, cap);
    // Only `cap` bytes are valid in slot->data; the task re-derives `cap` from
    // the original length (slot->len) and the current snap length.
    if (xQueueSend(self._workq, &idx, 0) != pdTRUE) {
        xQueueSend(self._freeq, &idx, 0);         // give the slot back
        Statistics::instance().noteDropped();
    }
    uint16_t waiting = uxQueueMessagesWaiting(self._workq);
    if (waiting > self._hwm) self._hwm = waiting;
}

// ---- capture processing task ----------------------------------------------
void Sniffer::captureTask(void* arg) {
    Sniffer* self = (Sniffer*)arg;
    uint16_t idx;
    for (;;) {
        if (xQueueReceive(self->_workq, &idx, portMAX_DELAY) == pdTRUE) {
            RawCap* slot = &((RawCap*)self->_pool)[idx];
            uint16_t snap = SettingsStore::instance().get().snap_len;
            if (snap > MAX_SNAP_LEN) snap = MAX_SNAP_LEN;
            uint16_t cap = slot->len < snap ? slot->len : snap;
            self->process(slot->data, cap, slot->rssi, slot->channel, slot->ts);
            // (slot->len holds the original on-air length for stats/pcap)
            xQueueSend(self->_freeq, &idx, 0);
        }
    }
}

void Sniffer::process(const uint8_t* data, uint16_t cap, int8_t rssi,
                      uint8_t channel, uint64_t ts) {
    ParsedFrame pf;
    if (!FrameParser::parse(data, cap, channel, rssi, ts, pf)) return;

    // Apply capture filters (frame-type mask + MAC/SSID + BPF).
    if (!Filter::instance().matches(pf)) return;

    RingBuffer::instance().push(pf, data, cap);
    Statistics::instance().ingest(pf);
    Detectors::instance().inspect(pf);

    Settings& s = SettingsStore::instance().get();
    if (s.pcap_enabled && PcapWriter::instance().isOpen()) {
        PcapWriter::instance().write(pf, data, cap);
    }
    StatusLed::instance().blip();
}

// ---- channel hopping -------------------------------------------------------
void Sniffer::hopNext() {
    Settings& s = SettingsStore::instance().get();
    for (int n = 0; n < MAX_CHANNELS; n++) {
        _hopIdx = (_hopIdx % MAX_CHANNELS) + 1;     // 1..MAX_CHANNELS
        if (s.channel_enabled[_hopIdx]) { setChannel(_hopIdx); return; }
    }
}

void Sniffer::serviceHop() {
    if (!_capturing) return;
    Settings& s = SettingsStore::instance().get();
    if (!s.channel_hop) { return; }

    // Keep the UI stable: lock to AP channel while a client is connected.
    if (s.hop_pause_on_client && _clientConnected) {
        if (_channel != s.ap_channel) setChannel(s.ap_channel);
        return;
    }
    uint32_t now = millis();
    if (now - _lastHopMs >= s.hop_interval_ms) {
        _lastHopMs = now;
        hopNext();
    }
}
