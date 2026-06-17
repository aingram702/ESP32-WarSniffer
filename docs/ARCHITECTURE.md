# WarSniffer architecture

## Capture pipeline

```
   Wi-Fi radio (promiscuous RX)
        │  esp_wifi promiscuous callback  [Wi-Fi task, core 0]
        ▼
   Sniffer::promiscuousCb
        │  copy snap-length bytes into a PSRAM pool slot, enqueue index
        ▼
   work queue ──► Sniffer::captureTask  [core 1]
                       │
                       ├─ FrameParser::parse   → ParsedFrame metadata
                       ├─ Filter::matches      → frame-type / MAC / SSID / BPF
                       ├─ RingBuffer::push     → PSRAM circular store (web list)
                       ├─ Statistics::ingest   → counters, AP/STA inventory, RSSI
                       ├─ Detectors::inspect   → IDS alerts
                       └─ PcapWriter::write    → LittleFS .pcap (+ radiotap)
        ▼
   WebInterface::pump  [main loop]  → WebSocket batches (frames + stats)
```

Back-pressure: the promiscuous callback never blocks. If the fixed PSRAM frame
pool is exhausted, the frame is dropped and counted (`stats.dropped`) rather
than stalling the Wi-Fi task.

## Modules (`src/`)

| File | Responsibility |
|---|---|
| `config.h` | Compile-time defaults |
| `types.h` | 802.11 structs, `ParsedFrame`, `Alert`, MAC helpers |
| `settings.*` | Runtime config persisted to NVS |
| `sniffer.*` | Promiscuous RX, frame pool/queues, channel hopping |
| `frame_parser.*` | Bounds-checked 802.11 → `ParsedFrame` decode |
| `filter.*` | MAC/SSID lists + BPF-style expression engine |
| `ring_buffer.*` | PSRAM circular store of captured frames |
| `statistics.*` | Counters, AP/STA inventory, fingerprinting, RSSI |
| `detector.*` | IDS engine + alert ring buffer |
| `oui_lookup.*` | MAC → vendor (curated table or `/oui.csv`) |
| `pcap_writer.*` | libpcap files with optional radiotap, rotation |
| `status_led.*` | WS2812 state indicator |
| `web_server.*` | REST API + WebSocket + static UI |
| `main.cpp` | Boot, SoftAP, captive portal, scheduler loop |

## Web UI (`data/www/`)

Vanilla single-page app — `index.html`, `style.css`, `app.js`, `logo.svg`.
No inline scripts (CSP-compliant) and no external/CDN dependencies. Live data
arrives over `/ws`; everything else is JSON under `/api/*`.

## Memory budget (PSRAM)

| Allocation | Size |
|---|---|
| Ring buffer pool (2048 × 512 B) | ~1 MB |
| Capture frame pool (128 × ~520 B) | ~66 KB |

AP/STA inventory and alert buffers are fixed-size and live in internal RAM.
