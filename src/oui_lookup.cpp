// ============================================================================
//  oui_lookup.cpp
// ============================================================================
#include "oui_lookup.h"
#include <LittleFS.h>
#include <pgmspace.h>

struct OuiEntry { uint32_t oui; const char* vendor; };

// Curated subset of frequently-seen OUIs. For full coverage drop the IEEE
// "oui.csv" (AABBCC,Vendor per line) onto LittleFS — it takes priority.
static const OuiEntry OUI_TABLE[] PROGMEM = {
    {0x000C29, "VMware"},      {0x005056, "VMware"},      {0x080027, "VirtualBox"},
    {0x001A11, "Google"},      {0x3C5AB4, "Google"},      {0xF4F5E8, "Google"},
    {0x001451, "Apple"},       {0x0017F2, "Apple"},       {0x3C0754, "Apple"},
    {0xAC87A3, "Apple"},       {0xF0DBF8, "Apple"},       {0xD0817A, "Apple"},
    {0x001D0F, "TP-Link"},     {0x50C7BF, "TP-Link"},     {0xC46E1F, "TP-Link"},
    {0x000D3A, "Microsoft"},   {0x0017FA, "Microsoft"},   {0x7C1E52, "Microsoft"},
    {0x001632, "Samsung"},     {0x0021D1, "Samsung"},     {0x5CF6DC, "Samsung"},
    {0x00056B, "Sony"},        {0x001315, "Sony"},        {0xFC0FE6, "Sony"},
    {0x001E58, "D-Link"},      {0x1CBDB9, "D-Link"},      {0xC8BE19, "D-Link"},
    {0x000FB5, "Netgear"},     {0x20E52A, "Netgear"},     {0xA040A0, "Netgear"},
    {0x0018F8, "Cisco-Linksys"},{0x002129, "Cisco"},      {0x00408C, "Axis"},
    {0x001B63, "Apple"},       {0x60FB42, "Apple"},       {0xE0ACCB, "Apple"},
    {0x001967, "Cisco"},       {0x00000C, "Cisco"},       {0x001A2F, "Cisco"},
    {0x18FE34, "Espressif"},   {0x240AC4, "Espressif"},   {0x3C71BF, "Espressif"},
    {0x7CDFA1, "Espressif"},   {0xA020A6, "Espressif"},   {0xB4E62D, "Espressif"},
    {0xDC4F22, "Espressif"},   {0xEC94CB, "Espressif"},   {0x84F3EB, "Espressif"},
    {0x001E2A, "Netgear"},     {0x0024B2, "Netgear"},     {0x9C3DCF, "Netgear"},
    {0x000E8F, "Sercomm"},     {0x002722, "Ubiquiti"},    {0x24A43C, "Ubiquiti"},
    {0x44D9E7, "Ubiquiti"},    {0x788A20, "Ubiquiti"},    {0xFCECDA, "Ubiquiti"},
    {0x0026BB, "Apple"},       {0x28CFE9, "Apple"},       {0x4C5704, "Roku"},
    {0xB827EB, "Raspberry Pi"},{0xDCA632, "Raspberry Pi"},{0xE45F01, "Raspberry Pi"},
    {0x001CBF, "Intel"},       {0x00A0C6, "Qualcomm"},    {0x000272, "CC&C"},
    {0x506583, "Belkin"},      {0x944452, "Belkin"},      {0xC05627, "Belkin"},
    {0x001A1E, "Aruba"},       {0x6CF37F, "Aruba"},       {0x9C1C12, "Aruba"},
    {0x002586, "Amazon"},      {0x44650D, "Amazon"},      {0xF0272D, "Amazon"},
    {0x68C63A, "Espressif"},   {0x8C4B14, "Espressif"},   {0x34AB95, "Espressif"},
};
static const size_t OUI_TABLE_LEN = sizeof(OUI_TABLE) / sizeof(OUI_TABLE[0]);

OuiLookup& OuiLookup::instance() {
    static OuiLookup o;
    return o;
}

void OuiLookup::begin() {
    _haveCsv = LittleFS.exists("/oui.csv");
    if (_haveCsv) log_i("OUI: using /oui.csv for vendor lookups");
}

bool OuiLookup::_csvLookup(uint32_t oui, char* out, size_t outLen) {
    File f = LittleFS.open("/oui.csv", "r");
    if (!f) return false;
    char target[7];
    snprintf(target, sizeof(target), "%06X", (unsigned)oui);
    bool found = false;
    while (f.available()) {
        String line = f.readStringUntil('\n');
        if (line.length() < 7) continue;
        // case-insensitive compare of first 6 hex chars
        if (strncasecmp(line.c_str(), target, 6) == 0 && line[6] == ',') {
            String v = line.substring(7);
            v.trim();
            strlcpy(out, v.c_str(), outLen);
            found = true;
            break;
        }
    }
    f.close();
    return found;
}

const char* OuiLookup::lookup(const uint8_t mac[6], char* out, size_t outLen) {
    out[0] = '\0';
    uint32_t oui = ((uint32_t)mac[0] << 16) | ((uint32_t)mac[1] << 8) | mac[2];

    if (_haveCsv && _csvLookup(oui, out, outLen)) return out;

    for (size_t i = 0; i < OUI_TABLE_LEN; i++) {
        uint32_t e = pgm_read_dword(&OUI_TABLE[i].oui);
        if (e == oui) {
            strncpy_P(out, (PGM_P)pgm_read_ptr(&OUI_TABLE[i].vendor), outLen);
            out[outLen - 1] = '\0';
            return out;
        }
    }
    if (isLocallyAdministered(mac)) strlcpy(out, "(randomized)", outLen);
    return out;
}
