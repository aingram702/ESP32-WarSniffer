# ESP32-WarSniffer

A self-contained **802.11 packet-capture appliance** for the
**ESP32-S3-DevKitC-1 (N16R8)** — a pocket Wireshark with a built-in,
hacker-styled web interface. It captures raw Wi-Fi frames in promiscuous /
monitor mode, hops channels, filters with a BPF-style language, writes
Wireshark-compatible PCAPs, and runs on-device intrusion detection (deauth
floods, evil twins, PMKID exposure, ARP spoofing, DNS anomalies, beacon
floods) — all over its own out-of-band Wi-Fi access point.

```
        )   (         WARSNIFFER
       (  )  )        802.11 packet recon
        )(  (         ── promiscuous · monitor · channel-hop · IDS ──
     .-"""""-.
    /  o   o  \
   |  ESP32-S3 |
    \  N16R8  /
     '-.....-'
```

> ⚠️ **Authorized use only.** Passive Wi-Fi monitoring and the capture of
> traffic you are not authorized to intercept may be illegal in your
> jurisdiction. Use WarSniffer only on networks you own or are explicitly
> permitted to test. The detection features are defensive; this project does
> **not** transmit attack frames.

---

## Features

**Capture**
- Promiscuous-mode capture of all frames on the current channel
- Monitor-mode (passive) capture of raw 802.11 management/control/data frames
- Channel hopping across 2.4 GHz channels 1–13/14 with configurable dwell time
- Configurable snap length and a PSRAM-backed circular capture buffer
- Microsecond timestamping (wall-clock synced from your browser for PCAP)

**Filtering**
- BPF-style expression language (see below)
- Frame-type capture mask (management / control / data)
- MAC allow/deny list (whitelist or blacklist)
- SSID include / exclude list
- Protocol filtering: ARP, DNS, DHCP, HTTP/TLS, EAPOL, IPv4/IPv6, TCP/UDP/ICMP

**Output**
- Wireshark-compatible **PCAP** files with optional **radiotap** headers
  (per-frame RSSI + channel), automatic size-based rotation, download & delete

**On-device intelligence**
- Live 802.11 frame parsing & decode (with hex view)
- Device fingerprinting + inventory (APs and stations, probed SSIDs)
- Traffic-statistics dashboard (pps history, per-channel, protocol mix)
- RSSI tracking (min/last/max per device)
- OUI vendor lookup (curated table; drop a full IEEE `oui.csv` for more)
- Optional geolocation tagging of a capture session
- **IDS:** deauth/disassoc flood, evil-twin AP, PMKID exposure, ARP spoofing,
  DNS anomaly, beacon flood detection — with a rate-limited alert feed
- **Cleartext credential harvesting** — extracts logins that cross the air
  unencrypted (HTTP Basic, HTTP login forms, FTP, POP3, IMAP, SMTP AUTH) into
  a dedicated *Creds* table (passwords masked by default)

**Platform**
- Self-hosted WPA2 access point for out-of-band management + captive portal
- Single-page web UI (no internet/CDN required), live WebSocket stream
- WS2812 status LED (boot / idle / capturing / alert / error)

---

## Hardware

| | |
|---|---|
| Board | ESP32-S3-DevKitC-1 **N16R8** (16 MB flash, 8 MB **octal** PSRAM) |
| LED | On-board addressable WS2812 on GPIO48 (default) |
| Power | USB-C (native USB CDC console enabled) |

PSRAM is **required** — the capture ring buffer and frame pool live there.

---

## Quick start

1. Install [PlatformIO](https://platformio.org/) (CLI or the VS Code extension).
2. Clone this repo and connect the board over the **native USB** port.
3. Flash the firmware and the web UI:

   ```bash
   pio run -t upload        # firmware
   pio run -t uploadfs      # web interface (LittleFS image from data/)
   pio device monitor       # optional serial console @115200
   ```

4. Join the Wi-Fi network **`WarSniffer`** (default password **`sniffsniff`**).
5. Browse to **http://192.168.4.1** — the captive portal should pop it open.
6. **Change the AP password immediately** in *Settings* (the UI nags until you do).

Capture starts automatically on boot, so the dashboard is live right away.

---

## BPF-style filter language

Filters are evaluated against decoded metadata and combine with
`and` / `or` / `not` and parentheses.

| Primitive | Example |
|---|---|
| Frame type | `type mgmt` · `type data` |
| Subtype | `subtype deauth` · `subtype beacon` · `subtype probe-req` |
| MAC | `wlan host aa:bb:cc:dd:ee:ff` · `wlan src ...` · `wlan dst ...` · `bssid ...` |
| Protocol | `proto arp` · `proto dns` · `proto eapol` · `proto http` |
| L3/L4 | `ip` · `ip6` · `tcp` · `udp` · `icmp` |
| Ports | `port 53` · `src port 80` · `dst port 443` |
| Radio | `channel 6` · `rssi > -70` |
| Network | `ssid "HomeNet"` |
| Flags | `pmkid` · `encrypted` |

Examples:

```
type mgmt and subtype deauth
proto eapol or pmkid
channel 6 and rssi > -65 and not encrypted
wlan host de:ad:be:ef:00:01 and type data
```

---

## Cleartext credential harvesting

The *Creds* tab lists credentials seen **in the clear**. WarSniffer never
decrypts anything — it can only read what is already plaintext on the air:

- The Wi-Fi must be unencrypted (an **open** network), since WPA2 data frames
  are encrypted and unreadable, **and**
- the application protocol must itself be plaintext.

Recognised sources: HTTP Basic auth, HTTP login-form bodies/query strings, and
the `USER`/`PASS`/`LOGIN`/`AUTH` exchanges of FTP, POP3, IMAP and SMTP.
Capture works best with **snap length at the maximum (512)** so request headers
and bodies are retained. Toggle the feature in *Settings → Detection*.

> This is an auditing aid for demonstrating the risk of unencrypted protocols on
> networks you are authorized to test. Do not use it to intercept traffic you
> have no permission to access.

## Channel hopping vs. the web UI

The radio is shared between the SoftAP (your management link) and capture.
While hopping, the AP leaves its home channel, which disrupts a connected
browser. WarSniffer defaults to **"lock to AP channel while UI connected"**
(*Settings → Capture*), giving you a stable UI that captures on the AP
channel. For full-spectrum sweeping, disable that option (or run headless,
logging to PCAP) — the UI will then be intermittent by design.

---

## Security notes

- Management runs on a **WPA2** SoftAP; an empty/short password falls back to an
  open network and the UI warns you.
- All API inputs are length-bounded and range-checked; JSON bodies are capped.
- PCAP downloads use a strict filename whitelist (no path traversal).
- Conservative security headers (CSP, `X-Frame-Options`, `nosniff`) on every
  response; the UI ships no inline scripts and pulls nothing from the internet.
- The device never transmits attack frames — detection is passive only.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the capture pipeline and
module layout.

---

## Optional: full OUI database

Vendor lookup ships with a small curated table. For full coverage, place the
IEEE OUI list at `data/oui.csv` (one `AABBCC,Vendor` per line) before
`pio run -t uploadfs`; it takes priority over the built-in table.

---

## License

MIT — see [`LICENSE`](LICENSE).
