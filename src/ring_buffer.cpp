// ============================================================================
//  ring_buffer.cpp
// ============================================================================
#include "ring_buffer.h"
#include <esp_heap_caps.h>

RingBuffer& RingBuffer::instance() {
    static RingBuffer r;
    return r;
}

bool RingBuffer::begin() {
    _cap = RING_CAPACITY_FRAMES;
    _mtx = xSemaphoreCreateMutex();
    if (!_mtx) return false;

    // Slot metadata array (small) — try PSRAM, fall back to internal RAM.
    _slots = (RingSlot*)heap_caps_calloc(_cap, sizeof(RingSlot),
                                         MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!_slots) {
        _slots = (RingSlot*)calloc(_cap, sizeof(RingSlot));
    }
    // Data pool (large) — must be PSRAM on N16R8.
    size_t poolBytes = (size_t)_cap * MAX_SNAP_LEN;
    _pool = (uint8_t*)heap_caps_malloc(poolBytes, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!_slots || !_pool) {
        log_e("RingBuffer: alloc failed (need PSRAM, %u bytes)", (unsigned)poolBytes);
        return false;
    }
    for (uint32_t i = 0; i < _cap; i++) {
        _slots[i].data = _pool + (size_t)i * MAX_SNAP_LEN;
        _slots[i].id   = 0;
    }
    log_i("RingBuffer: %u slots x %u bytes = %u KB in PSRAM",
          _cap, (unsigned)MAX_SNAP_LEN, (unsigned)(poolBytes / 1024));
    return true;
}

uint64_t RingBuffer::push(const ParsedFrame& meta, const uint8_t* data, uint16_t len) {
    if (!_slots) return 0;
    if (len > MAX_SNAP_LEN) len = MAX_SNAP_LEN;

    xSemaphoreTake(_mtx, portMAX_DELAY);
    uint32_t idx = _head;
    RingSlot& s = _slots[idx];
    s.id      = ++_total;
    s.meta    = meta;
    s.cap_len = len;
    if (data && len) memcpy(s.data, data, len);

    _head = (_head + 1) % _cap;
    if (_count < _cap) _count++;
    uint64_t id = s.id;
    xSemaphoreGive(_mtx);
    return id;
}

uint64_t RingBuffer::forEachSince(uint64_t sinceId, uint32_t max, const Visitor& fn) {
    if (!_slots) return sinceId;
    uint64_t highest = sinceId;
    xSemaphoreTake(_mtx, portMAX_DELAY);
    // Walk slots oldest-first. Oldest stored slot is at _head when full,
    // else at 0. Simpler: scan all slots, collect those with id>sinceId.
    // To emit oldest-first with a cap, we iterate the ring in chronological
    // order starting from the oldest entry.
    uint32_t start = (_count < _cap) ? 0 : _head;
    uint32_t emitted = 0;
    for (uint32_t i = 0; i < _count && emitted < max; i++) {
        uint32_t idx = (start + i) % _cap;
        const RingSlot& s = _slots[idx];
        if (s.id > sinceId) {
            fn(s);
            if (s.id > highest) highest = s.id;
            emitted++;
        }
    }
    xSemaphoreGive(_mtx);
    return highest;
}

bool RingBuffer::getById(uint64_t id, RingSlot& out, uint8_t* dataCopy, uint16_t dataCap) {
    if (!_slots || id == 0) return false;
    bool found = false;
    xSemaphoreTake(_mtx, portMAX_DELAY);
    for (uint32_t i = 0; i < _count; i++) {
        const RingSlot& s = _slots[i];
        if (s.id == id) {
            out = s;
            out.data = dataCopy;
            uint16_t n = s.cap_len < dataCap ? s.cap_len : dataCap;
            if (dataCopy) memcpy(dataCopy, s.data, n);
            out.cap_len = n;
            found = true;
            break;
        }
    }
    xSemaphoreGive(_mtx);
    return found;
}

void RingBuffer::clear() {
    if (!_slots) return;
    xSemaphoreTake(_mtx, portMAX_DELAY);
    _head = 0;
    _count = 0;
    // keep _total monotonic so cursors stay valid
    for (uint32_t i = 0; i < _cap; i++) _slots[i].id = 0;
    xSemaphoreGive(_mtx);
}
