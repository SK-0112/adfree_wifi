<div align="center">

<img src="docs/logo.svg" width="76" height="76" alt="AdFree logo">

# AdFree

**The $10 gadget that blocks ads on every device in your home.**

[**→ Install it from your browser**](https://SK-0112.github.io/adfree_wifi/)

No app. No subscription. No Raspberry Pi. No account.

[![Stars](https://img.shields.io/github/stars/SK-0112/adfree_wifi?style=flat&color=4f8cff)](https://github.com/SK-0112/adfree_wifi/stargazers)
[![License](https://img.shields.io/badge/license-MIT-37d39b)](LICENSE)
[![Platform](https://img.shields.io/badge/hardware-ESP32--S3-8b7bff)](#set-it-up-in-four-steps)
[![Install](https://img.shields.io/badge/install-from%20your%20browser-4f8cff)](https://SK-0112.github.io/adfree_wifi/)

</div>

---

AdFree turns a cheap ESP32-S3 board into a network-wide DNS ad blocker — the same
idea as Pi-hole, on a chip that costs less than lunch and draws less power than a
night light. Point your router at it once and every phone, laptop, smart TV,
console and guest device on your Wi-Fi gets filtered automatically, with nothing
installed on any of them.

## Set it up in four steps

| | |
|---|---|
| **1** | **Buy an ESP32-S3 board.** Search Amazon or Micro Center for *ESP32-S3 N16R8* — 16 MB flash and 8 MB PSRAM, about $7–12. The PSRAM is essential; a board without it won't work. Plus a USB-C cable that carries data. |
| **2** | **Plug it into your computer and open the [install page](https://SK-0112.github.io/adfree_wifi/).** Press Install, pick the board, wait a minute. Works in Chrome, Edge or Opera on Windows, Linux, macOS and ChromeOS. |
| **3** | **Tell it your Wi-Fi from your phone.** Power the board from any USB charger and join the `ADFREE-XXXX` network. Its password is unique to your board and printed on the install page's *Logs & Console* — write it down. Fill in the page that opens. |
| **4** | **Point your router at it.** Open `http://adblock.local`, note the IP, and set that as the DNS server in your router's DHCP settings. Done. |

Step 2 requires nothing installed on your computer — the browser talks to the
board over USB directly.

## Read this before you start

AdFree is useful but it is not magic, and it changes the internet for everyone in
the house. The honest version:

**Blocks well:** banner and display ads, analytics and tracking scripts, ads in
many free mobile apps, smart-TV telemetry, known malware and phishing domains.

**Cannot block:** YouTube ads, and in-app ads on Instagram, Facebook, TikTok and
Spotify. Those are served from the same domains as the content itself, so
blocking them would block the app. No DNS-based blocker can do this — if a
product claims otherwise, it isn't doing it with DNS.

**Quietly bypassed by:** Chrome/Firefox "secure DNS" (DNS-over-HTTPS),
Chromecasts and Google Home devices with hardcoded DNS, iCloud Private Relay,
VPNs, and phones once they leave your Wi-Fi for mobile data.

**The risks:**

- **Single point of failure.** Once the router points at AdFree, an unplugged
  board or a dead one means nobody in the house can browse until it's back or you
  undo the router setting. Know the undo procedure *before* you need it.
- **It affects everyone**, including guests and anyone working from home. Tell
  them first.
- **Some sites and apps will break** occasionally — use the pause button and the
  allow list.
- **It is not privacy or security software.** Your ISP still sees your traffic.
  It's not a VPN and not antivirus.
- **You become the household tech support.** If nobody wants that role, a
  browser extension like uBlock Origin is the lower-commitment choice.

**To undo everything:** log into your router, set the DNS field back to
*Automatic* / *Obtain from ISP*, save, reboot the router. Nothing AdFree does is
permanent and no device needs changing.

## Can the router step be automated?

No, and it's worth being clear why. Routers have no standard configuration API,
every brand's admin interface differs, and automating it would mean a tool
logging into your router with admin credentials — fragile and a bad security
idea. The board *could* run DHCP itself the way Pi-hole optionally does, but that
requires disabling your router's DHCP server first, which is harder than changing
one DNS field and makes a dead board take down the whole network instead of just
DNS.

So the [install page](https://SK-0112.github.io/adfree_wifi/#router) has
click-by-click instructions for the common router brands instead, plus per-device
instructions for iPhone, Android, Windows and macOS — which also let you try
AdFree on one device before committing the whole house.

## What you get

- **~490,000 blocked domains** from the three default lists, held in PSRAM and searched with a binary search
  over a sorted FNV-1a hash table. An entry for `doubleclick.net` also blocks
  `a.b.doubleclick.net`.
- **A dashboard** at `http://adblock.local` — live query and block counts, allow
  and deny lists, a pause button, blocklist URLs, upstream DNS settings.
- **Self-updating.** Blocklists refresh on a schedule. Firmware updates verify a
  SHA-256 digest before becoming bootable and roll back automatically if the new
  image can't stay healthy.
- **A status LED.** Green healthy · amber degraded · blue updating · purple
  paused · red no Wi-Fi · white pulse setup portal.
- **~0.4 W** continuous draw. Leave it plugged in behind the router.

## It fails open, on purpose

The design goal is that the worst case is "acts like a plain DNS relay", never
"the internet is down":

| If this happens | AdFree does this |
|---|---|
| Blocklist download fails | Keeps the previous list |
| New list looks implausible (<1000 domains) | Rejects it, keeps the previous one |
| Mid-swap of the blocklist table | Passes everything through |
| A query fails to parse | Forwards it rather than dropping it |
| Upstream resolver times out | Retries, then rotates to the next upstream |
| Main loop wedges for 90s | Task watchdog resets the board |
| A bad firmware image is installed | Reverts to the previous slot after 3 bad boots |
| Wi-Fi drops | Reconnects with backoff; falls back to the setup portal |

## Other ways to install

The browser installer is the recommended path. Two alternatives:

**Desktop flasher** — for offline flashing, or for baking Wi-Fi credentials into a
board you're posting to a relative so it joins their network on first power-up.
Runs on Windows, Linux and macOS.

```bash
pip install pyserial esptool
python adblock-esp32/setup_gui.py
```

**Command line** — writes the same prebuilt image the web installer uses.

```bash
python -m esptool --chip esp32s3 write-flash 0x0 docs/firmware/adfree-esp32s3-1.0.0.bin
```

On Linux, add yourself to the serial group first: `sudo usermod -aG dialout $USER`,
then log out and back in.

## Building from source

Requires [PlatformIO](https://platformio.org/).

```bash
python tools/build_release.py
```

That compiles `env:fresh`, merges the bootloader, partition table, boot selector
and application into one flat image, and writes it to `docs/firmware/` along with
the manifest the web installer reads. `env:fresh` can never contain credentials —
only `env:seeded` reads `src/seed_credentials.h`, and the build script refuses to
publish an image containing any string from that file.

Firmware internals, partition layout, HTTP endpoints and the OTA manifest format
are documented in [adblock-esp32/README.md](adblock-esp32/README.md).

### Testing the web installer locally

WebSerial treats `http://localhost` as a secure context, so you can exercise the
full install flow without publishing anything:

```bash
python tools/serve_installer.py
```

Open the printed URL in Chrome, Edge or Opera.

## Security notes

**No credentials are compiled into a release image.** `env:fresh` doesn't define
`ADBLOCK_ALLOW_SEED`, so `src/seed_credentials.h` is ignored no matter what it
contains, and `build_release.py` refuses to publish an image containing any
string from that file.

**The setup hotspot password is unique to each board.** It is drawn from the
ESP32's hardware RNG the first time the portal runs and stored in `config.json`.
It is deliberately *not* derived from the MAC address: the firmware is open
source and the MAC is broadcast as the AP's BSSID, so anything computed from it
could be reproduced by anyone in range. A single compiled-in password would be
worse — publishing this repo would hand out the key to every board ever flashed.

Read it from the serial console while the portal is running (the web installer's
*Logs & Console* view shows it), or from the dashboard once the board is on your
network.

**The dashboard password is chosen by you** during setup and stored as a SHA-256
hash. All HTTP endpoints sit behind Basic Auth. Note that Basic Auth over plain
HTTP on your LAN is not encrypted — treat the dashboard as trusted-network only.

## FAQ

**Which board exactly?** An ESP32-S3 DevKitC-1 style board sold as `ESP32-S3
N16R8`. The 8 MB PSRAM is what holds the blocklist — boards without it won't work.

**Will it break websites?** Occasionally. The dashboard has a one-click pause and
a per-domain allow list for that.

**My router won't let me change DNS.** Some ISP routers lock it. You can set the
DNS manually on individual devices instead and get the same result on those.

**The install button doesn't work.** Flashing needs WebSerial — Chrome, Edge or
Opera on a desktop. If you're on one of those, try a different USB cable; many are
charge-only.

**Is it really free?** Yes, MIT licensed. Nobody sells a finished unit — you buy
the $10 board and this repo turns it into the product.

## Contributing

Issues and pull requests are welcome. Useful things to help with:

- Router walkthroughs for brands not yet covered in [docs/index.html](docs/index.html)
- Testing on ESP32-S3 boards from different sellers
- Blocklist suggestions that keep the false-positive rate low

## Credits

AdFree is glue on top of other people's work. The short version:

- **[Pi-hole](https://pi-hole.net/)** established the idea of household-wide DNS
  blocking. This is an independent implementation sized for a microcontroller,
  not a fork — but the concept is theirs.
- **[ESP Web Tools](https://github.com/esphome/esp-web-tools)** (Nabu Casa /
  ESPHome) is what makes the browser installer possible at all.
- **[HaGeZi](https://github.com/hagezi/dns-blocklists)**,
  **[OISD](https://oisd.nl/)** and **[AdGuard](https://github.com/AdguardTeam/HostlistsRegistry)**
  maintain the blocklists. They are the reason this blocks anything; consider
  supporting them.
- **[ArduinoJson](https://arduinojson.org/)**,
  **[ESPAsyncWebServer / AsyncTCP](https://github.com/ESP32Async/ESPAsyncWebServer)**,
  **[Adafruit NeoPixel](https://github.com/adafruit/Adafruit_NeoPixel)**,
  **[arduino-esp32](https://github.com/espressif/arduino-esp32)**,
  **[ESP-IDF](https://github.com/espressif/esp-idf)**,
  **[PlatformIO](https://platformio.org/)** and
  **[esptool](https://github.com/espressif/esptool)** do the actual work.

Full list, versions and licences: **[CREDITS.md](CREDITS.md)**.

## Licence

This project's own source is MIT — see [LICENSE](LICENSE).

Note that the firmware links several **LGPL-3.0** libraries (ESPAsyncWebServer,
AsyncTCP, Adafruit NeoPixel) and the LGPL-2.1 Arduino core, so the prebuilt
binary in `docs/firmware/` is a combined work. The relinking requirement is met
by publishing the complete source, pinned dependency versions and a one-command
reproducible build. See the licensing note in [CREDITS.md](CREDITS.md) before
shipping this commercially.

Not affiliated with Pi-hole.
