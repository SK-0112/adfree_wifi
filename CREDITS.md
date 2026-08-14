# Credits

AdFree is a thin layer of glue on top of a great deal of other people's work.
Everything below is doing more of the heavy lifting than this repository is.

## The idea

**[Pi-hole](https://pi-hole.net/)** — Jacob Salmela and contributors.
Pi-hole established network-wide DNS blocking as something an ordinary household
could run, and every design decision here is measured against it. AdFree is not
affiliated with, endorsed by, or derived from the Pi-hole codebase; it is an
independent implementation of the same idea sized to fit a microcontroller.

## Firmware libraries

These are compiled into the image that this project distributes.

| Library | Version | Licence | Author |
|---|---|---|---|
| [ArduinoJson](https://arduinojson.org/) | 7.4.3 | MIT | Benoît Blanchon |
| [ESPAsyncWebServer](https://github.com/ESP32Async/ESPAsyncWebServer) | 3.12.0 | LGPL-3.0 | ESP32Async, originally Hristo Gochkov |
| [AsyncTCP](https://github.com/ESP32Async/AsyncTCP) | 3.5.0 | LGPL-3.0 | ESP32Async, originally Hristo Gochkov |
| [Adafruit NeoPixel](https://github.com/adafruit/Adafruit_NeoPixel) | 1.15.5 | LGPL-3.0 | Adafruit Industries |

## Platform and toolchain

| Project | Licence | Used for |
|---|---|---|
| [arduino-esp32](https://github.com/espressif/arduino-esp32) | LGPL-2.1 | the Arduino core for the ESP32-S3 |
| [ESP-IDF](https://github.com/espressif/esp-idf) | Apache-2.0 | underlying SDK: Wi-Fi, LittleFS, OTA, watchdog, RNG |
| [PlatformIO](https://platformio.org/) | Apache-2.0 | build system and dependency management |
| [esptool](https://github.com/espressif/esptool) | GPL-2.0 | flashing and merging the release image |
| [pySerial](https://github.com/pyserial/pyserial) | BSD-3-Clause | serial port detection in the desktop flasher |

## The browser installer

**[ESP Web Tools](https://github.com/esphome/esp-web-tools)** — Nabu Casa and the
ESPHome project, Apache-2.0. This is the single component that makes AdFree
installable by a non-technical person: it flashes the board over WebSerial with
nothing installed on the user's computer. The entire "press a button in your
browser" experience is theirs, not ours.

## Blocklists

These are downloaded by the device at runtime and are **not** redistributed in
this repository or in the firmware image. They remain the property of their
maintainers, under their own terms.

| List | Licence / terms | Maintainer |
|---|---|---|
| [HaGeZi Pro++](https://github.com/hagezi/dns-blocklists) | GPL-3.0 | HaGeZi |
| [OISD Big](https://oisd.nl/) | free to use, see site | Steven Black-adjacent, maintained by oisd |
| [AdGuard Base filter](https://github.com/AdguardTeam/HostlistsRegistry) | GPL-3.0 | AdGuard |

Maintaining a blocklist is thankless, unending work and it is the reason this
project blocks anything at all. If you find AdFree useful, consider supporting
these maintainers directly.

## Website

- [Shields.io](https://shields.io/) — README badges

No web fonts, analytics, trackers or third-party scripts are used on the landing
page beyond ESP Web Tools itself.

## A note on licensing

AdFree's own source is MIT. However, the firmware links **ESPAsyncWebServer,
AsyncTCP and Adafruit NeoPixel, which are LGPL-3.0**, and the Arduino core, which
is LGPL-2.1. The prebuilt binary in `docs/firmware/` is therefore a combined work
containing LGPL components.

LGPL-3.0 §4 requires that anyone receiving such a binary be able to relink it
against a modified version of those libraries. This project satisfies that in the
way the ESP32 ecosystem conventionally does: the complete source, the exact
dependency versions, and the full build recipe are public, and anyone can
reproduce or modify the image with a single command:

```bash
python tools/build_release.py
```

If you intend to ship AdFree commercially, or in a product where that
reproducibility does not hold, get your own legal advice — do not rely on this
paragraph.
