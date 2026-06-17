// ============================================================================
//  sniffer.h  —  Promiscuous / monitor-mode capture engine + channel hopping
//
//  Pipeline:
//    esp_wifi promiscuous RX  (Wi-Fi task)
//        -> copy snap-length bytes into a PSRAM pool slot, enqueue
//    capture task (processCapture)
//        -> parse -> filter -> ring buffer / stats / detectors / pcap / LED
//
//  Channel hopping cycles the enabled 2.4 GHz channels. Because the SoftAP
//  shares the single radio, hopping disrupts the management UI; when
//  `hop_pause_on_client` is set and a web client is connected the radio is
//  locked to the AP channel for a stable UI (full-spectrum logging then
//  requires disconnecting the client — true headless operation).
// ============================================================================
#pragma once

#include <Arduino.h>
#include <esp_wifi_types.h>
#include "config.h"

class Sniffer {
public:
    static Sniffer& instance();

    bool begin();              // alloc pool/queues, create capture task
    void startCapture();       // enable promiscuous RX
    void stopCapture();        // disable promiscuous RX
    bool isCapturing() const { return _capturing; }

    void applyChannelConfig(); // re-read Settings (hop on/off, channels)
    void setClientConnected(bool c) { _clientConnected = c; }

    uint8_t  currentChannel() const { return _channel; }
    uint64_t queueHighWater() const { return _hwm; }

    // Called from the periodic 1 Hz tick in main.
    void serviceHop();

private:
    Sniffer() {}

    static void promiscuousCb(void* buf, wifi_promiscuous_pkt_type_t type);
    static void captureTask(void* arg);
    void process(const uint8_t* data, uint16_t len, int8_t rssi, uint8_t channel, uint64_t ts);
    void hopNext();
    void setChannel(uint8_t ch);

    volatile bool _capturing = false;
    volatile bool _clientConnected = false;
    volatile uint8_t _channel = DEFAULT_CHANNEL;
    uint32_t _lastHopMs = 0;
    uint8_t  _hopIdx = 0;
    uint64_t _hwm = 0;

    void* _pool = nullptr;              // RawCap[POOL_N] in PSRAM
    QueueHandle_t _freeq = nullptr;     // indices available
    QueueHandle_t _workq = nullptr;     // indices with captured data
    TaskHandle_t  _task  = nullptr;
};
