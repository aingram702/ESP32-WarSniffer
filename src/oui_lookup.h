// ============================================================================
//  oui_lookup.h  —  MAC OUI -> vendor name
//
//  Ships with a curated table of common vendors embedded in flash. If a fuller
//  IEEE database is present at /oui.csv on LittleFS (format: "AABBCC,Vendor"),
//  it is consulted first. Also reports locally-administered / multicast bits.
// ============================================================================
#pragma once

#include <Arduino.h>

class OuiLookup {
public:
    static OuiLookup& instance();
    void begin();                       // detect optional /oui.csv

    // Returns vendor name, or "" if unknown. `out` must hold >=48 bytes.
    const char* lookup(const uint8_t mac[6], char* out, size_t outLen);

    bool isLocallyAdministered(const uint8_t mac[6]) const { return mac[0] & 0x02; }
    bool isMulticast(const uint8_t mac[6]) const           { return mac[0] & 0x01; }

private:
    OuiLookup() {}
    bool _haveCsv = false;
    bool _csvLookup(uint32_t oui, char* out, size_t outLen);
};
