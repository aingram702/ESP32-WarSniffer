// ============================================================================
//  status_led.h  —  WS2812 RGB status indicator (GPIO48 on DevKitC-1)
//
//  Colour / pattern conveys device state at a glance:
//    BOOT      : white  pulse
//    IDLE      : dim blue breathing      (AP up, not capturing)
//    CAPTURING : green  blink on each batch of frames
//    ALERT     : red    fast flash        (active IDS alert)
//    ERROR     : red    solid
// ============================================================================
#pragma once

#include <Arduino.h>

enum LedState : uint8_t {
    LED_BOOT = 0,
    LED_IDLE,
    LED_CAPTURING,
    LED_ALERT,
    LED_ERROR,
};

class StatusLed {
public:
    static StatusLed& instance();
    void begin();
    void setState(LedState s);
    void blip();                 // brief green flash (frame activity)
    void tick();                 // call frequently from a task/loop
private:
    StatusLed() {}
    void write(uint8_t r, uint8_t g, uint8_t b);
    volatile LedState _state = LED_BOOT;
    volatile uint32_t _blipUntil = 0;
    uint32_t _phase = 0;
};
