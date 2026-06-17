// ============================================================================
//  web_server.h  —  Async HTTP REST API + WebSocket live capture stream
// ============================================================================
#pragma once

#include <Arduino.h>

class AsyncWebServer;
class AsyncWebSocket;
class AsyncWebSocketClient;
class AsyncWebServerRequest;

class WebInterface {
public:
    static WebInterface& instance();
    void begin();

    // Push new captured frames + periodic stats to WebSocket clients.
    // Call frequently from the main loop (it self-rate-limits).
    void pump();

    uint32_t clientCount() const;

private:
    WebInterface() {}
    void routes();
    void onWsEvent(AsyncWebSocket* server, AsyncWebSocketClient* client,
                   uint8_t type, void* arg, uint8_t* data, size_t len);

    AsyncWebServer*  _server = nullptr;
    AsyncWebSocket*  _ws = nullptr;

    uint64_t _frameCursor = 0;     // last ring id streamed
    uint32_t _alertCursor = 0;     // last alert id streamed
    uint32_t _lastFramePushMs = 0;
    uint32_t _lastStatsPushMs = 0;
};
