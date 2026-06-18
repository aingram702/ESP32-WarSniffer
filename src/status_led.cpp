// ============================================================================
//  status_led.cpp
// ============================================================================
#include "status_led.h"
#include "config.h"

StatusLed& StatusLed::instance() {
    static StatusLed s;
    return s;
}

void StatusLed::begin() {
    _state = LED_BOOT;
    write(LED_BRIGHTNESS, LED_BRIGHTNESS, LED_BRIGHTNESS);
}

void StatusLed::setState(LedState s) {
    _state = s;
}

void StatusLed::blip() {
    _blipUntil = millis() + 40;
}

static inline uint8_t scale(uint8_t v) {
    return (uint16_t)v * LED_BRIGHTNESS / 255;
}

void StatusLed::write(uint8_t r, uint8_t g, uint8_t b) {
    // Drive the on-board WS2812. rgbLedWrite() exists on Arduino-ESP32 3.x;
    // neopixelWrite() is the equivalent on the 2.0.x core used here.
#if defined(ARDUINO_ESP32_RELEASE_3_0_0) || ESP_ARDUINO_VERSION_MAJOR >= 3
    rgbLedWrite(WARSNIFFER_LED_PIN, r, g, b);
#else
    neopixelWrite(WARSNIFFER_LED_PIN, r, g, b);
#endif
}

void StatusLed::tick() {
    uint32_t now = millis();
    _phase = now;

    // Active alert always wins (except hard error).
    if (_state == LED_ERROR) {
        write(LED_BRIGHTNESS, 0, 0);
        return;
    }
    if (_state == LED_ALERT) {
        bool on = (now / 120) & 1;
        write(on ? LED_BRIGHTNESS : 0, 0, 0);
        return;
    }
    if (now < _blipUntil) {
        write(0, LED_BRIGHTNESS, 0);
        return;
    }

    switch (_state) {
        case LED_BOOT: {
            uint8_t v = (uint8_t)((sin(now / 250.0) * 0.5 + 0.5) * LED_BRIGHTNESS);
            write(v, v, v);
            break;
        }
        case LED_CAPTURING: {
            // dim green breathing baseline; blips overlay brighter green
            uint8_t v = (uint8_t)((sin(now / 600.0) * 0.5 + 0.5) * (LED_BRIGHTNESS / 3));
            write(0, v + 2, 0);
            break;
        }
        case LED_IDLE:
        default: {
            uint8_t v = (uint8_t)((sin(now / 900.0) * 0.5 + 0.5) * (LED_BRIGHTNESS / 3));
            write(0, 0, v + 2);
            break;
        }
    }
}
