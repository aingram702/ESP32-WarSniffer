// ============================================================================
//  pcap_writer.cpp
// ============================================================================
#include "pcap_writer.h"
#include "settings.h"
#include "config.h"
#include <LittleFS.h>

PcapWriter& PcapWriter::instance() { static PcapWriter p; return p; }

void PcapWriter::begin() {
    _mtx = xSemaphoreCreateMutex();
    if (!LittleFS.exists(PCAP_DIR)) LittleFS.mkdir(PCAP_DIR);
}

void PcapWriter::setEpochBase(uint64_t epochSec, uint64_t atMicros) {
    _epochSec  = epochSec;
    _epochAtUs = atMicros;
}

void PcapWriter::resolveTimestamp(uint64_t us, uint32_t& sec, uint32_t& usec) {
    if (_epochSec) {
        int64_t delta = (int64_t)us - (int64_t)_epochAtUs;   // since base
        int64_t total = (int64_t)_epochSec * 1000000 + delta;
        if (total < 0) total = 0;
        sec  = (uint32_t)(total / 1000000);
        usec = (uint32_t)(total % 1000000);
    } else {
        sec  = (uint32_t)(us / 1000000);
        usec = (uint32_t)(us % 1000000);
    }
}

void PcapWriter::writeGlobalHeader() {
    struct __attribute__((packed)) {
        uint32_t magic; uint16_t vmaj, vmin; int32_t thiszone;
        uint32_t sigfigs, snaplen, network;
    } gh = {
        0xa1b2c3d4, 2, 4, 0, 0, MAX_SNAP_LEN + 32,
        (uint32_t)(_radiotap ? PCAP_LINKTYPE_RADIOTAP : PCAP_LINKTYPE_802_11)
    };
    _file.write((uint8_t*)&gh, sizeof(gh));
    _bytes += sizeof(gh);
}

bool PcapWriter::start() {
    if (!_mtx) return false;
    xSemaphoreTake(_mtx, portMAX_DELAY);
    Settings& s = SettingsStore::instance().get();
    _radiotap = s.pcap_radiotap;
    _maxBytes = s.pcap_max_bytes;

    // filename: /pcap/cap-<bootms>.pcap  (monotonic, collision-free)
    snprintf(_path, sizeof(_path), "%s/cap-%lu.pcap", PCAP_DIR, (unsigned long)millis());
    _file = LittleFS.open(_path, "w");
    if (!_file) { xSemaphoreGive(_mtx); return false; }
    _bytes = 0; _frames = 0;
    writeGlobalHeader();
    xSemaphoreGive(_mtx);
    log_i("PCAP: started %s (radiotap=%d)", _path, _radiotap);
    return true;
}

void PcapWriter::stop() {
    if (!_mtx) return;
    xSemaphoreTake(_mtx, portMAX_DELAY);
    if (_file) { _file.flush(); _file.close(); }
    xSemaphoreGive(_mtx);
}

bool PcapWriter::rotateIfNeeded() {
    if (_maxBytes && _bytes >= _maxBytes) {
        _file.flush(); _file.close();
        snprintf(_path, sizeof(_path), "%s/cap-%lu.pcap", PCAP_DIR, (unsigned long)millis());
        _file = LittleFS.open(_path, "w");
        if (!_file) return false;
        _bytes = 0; _frames = 0;
        writeGlobalHeader();
    }
    return true;
}

// Build a minimal radiotap header (Rate + Channel + dBm antenna signal).
static uint16_t buildRadiotap(uint8_t* rt, uint8_t channel, int8_t rssi) {
    memset(rt, 0, 16);
    rt[0] = 0;  // version
    rt[1] = 0;  // pad
    uint32_t present = (1u << 2) | (1u << 3) | (1u << 5);  // Rate, Channel, Signal
    rt[4] = present & 0xFF; rt[5] = (present >> 8) & 0xFF;
    rt[6] = (present >> 16) & 0xFF; rt[7] = (present >> 24) & 0xFF;
    uint16_t off = 8;
    rt[off++] = 0x02;                       // Rate (1 Mb/s units) placeholder
    if (off & 1) off++;                     // Channel align to 2
    uint16_t freq = (channel == 14) ? 2484 : (2412 + (channel - 1) * 5);
    rt[off++] = freq & 0xFF; rt[off++] = (freq >> 8) & 0xFF;
    uint16_t chflags = 0x00A0;              // 2GHz + dynamic CCK/OFDM
    rt[off++] = chflags & 0xFF; rt[off++] = (chflags >> 8) & 0xFF;
    rt[off++] = (uint8_t)rssi;              // dBm antenna signal (signed)
    rt[2] = off & 0xFF; rt[3] = (off >> 8) & 0xFF;  // total radiotap length
    return off;
}

void PcapWriter::write(const ParsedFrame& meta, const uint8_t* data, uint16_t len) {
    if (!_mtx) return;
    xSemaphoreTake(_mtx, portMAX_DELAY);
    if (!_file) { xSemaphoreGive(_mtx); return; }
    if (!rotateIfNeeded()) { xSemaphoreGive(_mtx); return; }

    uint8_t rt[16];
    uint16_t rtlen = _radiotap ? buildRadiotap(rt, meta.channel, meta.rssi) : 0;

    uint32_t sec, usec;
    resolveTimestamp(meta.timestamp_us, sec, usec);

    uint32_t incl = rtlen + len;
    uint32_t orig = rtlen + meta.length;    // original on-air length
    struct __attribute__((packed)) {
        uint32_t ts_sec, ts_usec, incl_len, orig_len;
    } rh = { sec, usec, incl, orig };

    _file.write((uint8_t*)&rh, sizeof(rh));
    if (rtlen) _file.write(rt, rtlen);
    if (len)   _file.write(data, len);
    _bytes += sizeof(rh) + incl;
    _frames++;
    xSemaphoreGive(_mtx);
}
