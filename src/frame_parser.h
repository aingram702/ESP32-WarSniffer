// ============================================================================
//  frame_parser.h  —  Decode raw 802.11 frames into ParsedFrame metadata
// ============================================================================
#pragma once

#include <Arduino.h>
#include "types.h"

namespace FrameParser {

// Decode `buf` (len bytes) captured on `channel` with `rssi`. Fills `out`.
// Returns true if at least the MAC header was decodable.
bool parse(const uint8_t* buf, uint16_t len, uint8_t channel, int8_t rssi,
           uint64_t timestamp_us, ParsedFrame& out);

// Human-readable subtype name (e.g. "Beacon", "Deauth", "QoS Data").
const char* subtypeName(uint8_t type, uint8_t subtype);
const char* typeName(uint8_t type);

}  // namespace FrameParser
