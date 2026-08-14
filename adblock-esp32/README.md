# AdFree firmware internals

Implementation notes for the ESP32-S3 N16R8 DNS blocker. For installation, see
the [main README](../README.md) or the [web installer](https://SK-0112.github.io/adfree_wifi/).

## Target hardware
- ESP32-S3 (QFN56), dual core 240 MHz
- 16 MB flash, 8 MB embedded PSRAM (quad SPI) — the PSRAM holds the blocklist
- Native USB-Serial/JTAG

## Build environments
| env | credentials | use |
|-----|-------------|-----|
| `fresh` | none, ever | the release build; boots into the setup portal |
| `seeded` | from `src/seed_credentials.h` | local development only, never publish |

Only `env:seeded` defines `ADBLOCK_ALLOW_SEED`, so `main.cpp` cannot pick up a
stray `seed_credentials.h` in a release build.

    pio run -e fresh -t upload        # release image
    pio run -e seeded -t upload       # with your Wi-Fi baked in

To produce the publishable merged image plus the web-installer manifest:

    python ../tools/build_release.py

That merges bootloader (0x0), partition table (0x8000), boot selector (0xE000)
and application (0x10000) into one flat image written at offset 0. Because the
merged image includes otadata, flashing it also clears the OTA selector — a
board that last booted from `app1` will correctly boot the newly written `app0`.
Flashing only `firmware.bin` does not, and needs this first:

    python -m esptool --port COM5 erase-region 0xE000 0x2000

## Layout (partitions.csv)
| partition | offset    | size   | purpose                         |
|-----------|-----------|--------|---------------------------------|
| nvs       | 0x9000    | 20 KB  | OTA rollback guard counters     |
| otadata   | 0xE000    | 8 KB   | active-slot selector            |
| app0      | 0x10000   | 3 MB   | firmware slot A                 |
| app1      | 0x310000  | 3 MB   | firmware slot B (OTA target)    |
| spiffs    | 0x610000  | 9.8 MB | LittleFS: config, blocklist, log|
| coredump  | 0xFE0000  | 64 KB  | panic dumps                     |

## How blocking works
Blocklists are downloaded, parsed (hosts / bare-domain / AdBlock-Plus syntax),
hashed with FNV-1a 64, sorted and deduplicated, then held as a sorted array in
PSRAM. Lookups are a binary search that also walks up the label hierarchy, so an
entry for `doubleclick.net` also blocks `a.b.doubleclick.net`. Blocked names get
`0.0.0.0` (A) / `::` (AAAA); other qtypes get NODATA.

The three default lists deduplicate to ~490k domains ≈ 3.7 MB of PSRAM against
a `MAX_DOMAINS` cap of 700k, leaving >4 MB free. The table is persisted to
LittleFS so a reboot reloads it in <1s with no download.

## Fail-safe behaviour (this is the important part)
The device is designed so that its failure mode is "acts like a plain DNS relay",
never "the internet is down":
- Blocklist download fails      -> previous list stays active
- New list looks implausible    -> rejected (<1000 domains), previous kept
- During the table swap         -> passes everything through (fail-open)
- Query parse failure           -> forwarded, never dropped
- Upstream times out            -> retried on the next upstream, then rotated
- Main loop wedges >90s         -> task watchdog resets the board
- Bad firmware installed        -> reverts to the previous slot after 3 bad boots
- Wi-Fi lost                    -> reconnect with backoff; can't connect -> setup portal

## Endpoints (HTTP Basic Auth on everything)
| method | path             | purpose                                  |
|--------|------------------|------------------------------------------|
| GET    | /                | dashboard                                |
| GET    | /api/status      | full JSON state                          |
| POST   | /api/toggle      | blocker on/off                           |
| POST   | /api/pause?secs= | -1 indefinite, 0 resume, N seconds       |
| POST   | /api/refresh     | refresh blocklists now                   |
| POST   | /api/lists       | whitelist / blacklist / blocklist URLs   |
| POST   | /api/settings    | upstreams, intervals, OTA url, static IP |
| POST   | /api/admin       | change admin login or Wi-Fi credentials  |
| POST   | /api/otacheck    | check manifest and update                |
| POST   | /api/upload      | manual firmware upload                   |
| POST   | /api/reboot      | restart                                  |

## OTA
Point `ota_manifest_url` at a JSON file:

    {"version":"1.0.4","url":"https://host/fw.bin","sha256":"<64 hex chars>"}

The image is streamed into the inactive slot and hashed as it arrives; a digest
mismatch aborts before anything becomes bootable. On reboot a guard counter arms;
the new image must stay healthy (Wi-Fi + DNS) for 60s or the device reverts after
3 failed boots. The version string is only committed once verified.

## LED (GPIO48, dim)
green heartbeat = healthy · amber = degraded · blue blink = updating ·
red = error/no Wi-Fi · purple = paused · white pulse = setup portal

## Provisioning a board

Three paths, in order of how little the user has to install:

1. **Web installer** — `docs/index.html` on GitHub Pages, via
   [ESP Web Tools](https://esphome.github.io/esp-web-tools/). Writes the merged
   image over WebSerial. Chrome/Edge/Opera on any desktop OS.
2. **`setup_gui.py`** — desktop flasher, Windows/Linux/macOS. Writes the same
   prebuilt image with esptool (fast, no compiler), or compiles `env:seeded`
   when you want credentials baked in.
3. **Command line:**

       python -m esptool --chip esp32s3 write-flash 0x0 ../docs/firmware/adfree-esp32s3-*.bin

In modes 1 and 3 the board comes up unprovisioned and opens its `ADFREE-XXXX`
hotspot; Wi-Fi is entered from a phone. The hotspot password is generated per
device from the hardware RNG on first boot, stored in `config.json`, printed to
serial while the portal runs, and shown on the dashboard once provisioned. `setup_gui.py` writes
`src/seed_credentials.h` (gitignored — it holds a Wi-Fi password) only in the
bake-it-in mode.
