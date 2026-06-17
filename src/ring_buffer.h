// ============================================================================
//  ring_buffer.h  —  PSRAM-backed circular store of captured frames
//
//  Pre-allocates a fixed pool of slots in PSRAM (no per-frame malloc on the
//  capture path -> no heap fragmentation). The newest RING_CAPACITY_FRAMES
//  frames are retained; older frames are overwritten. Each frame is tagged
//  with a monotonically increasing 64-bit id so the web layer can poll for
//  "everything newer than id X".
// ============================================================================
#pragma once

#include <Arduino.h>
#include <functional>
#include "types.h"
#include "config.h"

struct RingSlot {
    uint64_t    id;             // global sequence number (0 = empty)
    ParsedFrame meta;
    uint16_t    cap_len;
    uint8_t*    data;           // points into the PSRAM data pool
};

class RingBuffer {
public:
    static RingBuffer& instance();

    bool begin();               // allocate pool in PSRAM

    // Copy a frame into the buffer. Thread-safe. Returns the assigned id.
    uint64_t push(const ParsedFrame& meta, const uint8_t* data, uint16_t len);

    uint64_t totalCaptured() const { return _total; }
    uint32_t stored() const { return _count; }
    uint32_t capacity() const { return _cap; }

    // Visit up to `max` slots with id > sinceId, oldest-first. The callback
    // receives a const reference valid only for the duration of the call.
    // Returns the highest id visited (so the caller can advance its cursor).
    typedef std::function<void(const RingSlot&)> Visitor;
    uint64_t forEachSince(uint64_t sinceId, uint32_t max, const Visitor& fn);

    // Fetch a single slot by id into caller storage. Returns false if evicted.
    bool getById(uint64_t id, RingSlot& out, uint8_t* dataCopy, uint16_t dataCap);

    void clear();

private:
    RingBuffer() {}
    RingSlot*       _slots = nullptr;
    uint8_t*        _pool  = nullptr;   // _cap * MAX_SNAP_LEN bytes
    uint32_t        _cap   = 0;
    volatile uint32_t _head = 0;        // next write position
    volatile uint32_t _count = 0;
    volatile uint64_t _total = 0;
    SemaphoreHandle_t _mtx = nullptr;
};
