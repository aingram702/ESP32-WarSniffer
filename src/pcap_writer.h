// ============================================================================
//  pcap_writer.h  —  libpcap-format capture files on LittleFS
//
//  Optionally prepends a minimal radiotap header (LINKTYPE_IEEE80211_RADIOTAP)
//  carrying channel + RSSI so Wireshark shows signal strength. Files rotate at
//  a configurable size and live under /pcap. Wall-clock time is taken from a
//  base epoch the UI syncs from the browser (the device has no RTC).
// ============================================================================
#pragma once

#include <Arduino.h>
#include <FS.h>
#include "types.h"

class PcapWriter {
public:
    static PcapWriter& instance();
    void begin();

    bool start();                 // open a new capture file (uses Settings)
    void stop();
    bool isOpen() const { return _file; }

    // Append a frame. Safe to call when closed (no-op). Thread: capture task.
    void write(const ParsedFrame& meta, const uint8_t* data, uint16_t len);

    void setEpochBase(uint64_t epochSec, uint64_t atMicros);

    const char* currentPath() const { return _path; }
    uint32_t    bytesWritten() const { return _bytes; }
    uint32_t    framesWritten() const { return _frames; }

private:
    PcapWriter() {}
    void writeGlobalHeader();
    bool rotateIfNeeded();
    void resolveTimestamp(uint64_t us, uint32_t& sec, uint32_t& usec);

    File      _file;
    char      _path[48] = {0};
    bool      _radiotap = true;
    uint32_t  _bytes = 0;
    uint32_t  _frames = 0;
    uint32_t  _maxBytes = 0;
    SemaphoreHandle_t _mtx = nullptr;

    uint64_t  _epochSec = 0;       // wall-clock base (0 => unknown, ts from boot)
    uint64_t  _epochAtUs = 0;
};
