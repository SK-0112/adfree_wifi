# AdFree firmware internals

Implementation notes for the ESP32-S3 N16R8 DNS blocker. For installation, see
the [main README](../README.md) or the [web installer](https://SK-0112.github.io/adfree_wifi/).

## Target hardware
- ESP32-S3 (QFN56), dual core 240 MHz
- 16 MB flash, 8 MB embedded PSRAM (octal SPI, `qio_opi`). The PSRAM holds the blocklist
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

To produce the publishable images plus both manifests:

    python ../tools/build_release.py

That writes `docs/firmware/adfree-esp32s3-<ver>.bin` (merged, for USB installs),
`docs/firmware/adfree-esp32s3-app-<ver>.bin` plus `docs/firmware/ota.json` (what
boards download for over-the-air updates), and `docs/manifest.json` (ESP Web
Tools). The version lives in `src/version.h`.

## Dashboard

The dashboard source is `web/index.html`, a single self-contained page. Before
every build `scripts/embed_web.py` gzips it into `src/web_page.h`; the board
serves it pre-compressed (about 20 KB) with an ETag, so a reload costs a 304.
The page polls small JSON endpoints and stops polling while its tab is hidden.

To work on it without a board:

    python test/mock_server.py      # http://localhost:8080, synthetic data

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
Blocklists are downloaded, parsed (hosts / bare-domain / AdGuard-ABP syntax),
hashed with FNV-1a 64, sorted and deduplicated, then held as a sorted array in
PSRAM. Lookups are a binary search that also walks up the label hierarchy, so an
entry for `doubleclick.net` also blocks `a.b.doubleclick.net`. Blocked names get
`0.0.0.0` (A) / `::` (AAAA); other qtypes get NODATA with an SOA so clients
cache the answer.

Parsing rules (`src/list_parse.h`, tested by `test/test_parse.cpp`):
- `@@` exception rules are skipped on purpose. In AdGuard Home they un-block ad
  domains other lists block (`cdn.taboola.com`, `www.googleadservices.com`). The
  allowlist is the escape hatch for anything that breaks.
- Rules with modifiers other than `$important` are skipped, so `$badfilter`,
  `$client`, `$dnstype` and `$denyallow` never become unconditional blocks.
- Wildcards other than a leading `*.` are skipped.

The allow and deny lists are hash tables too. The most specific match wins; at
the same level allow beats deny. `use-application-dns.net`, `mask.icloud.com`
and `mask-h2.icloud.com` always get NXDOMAIN while blocking is on, which keeps
Firefox off its built-in DoH and turns off iCloud Private Relay on this network.

The four default lists come to about 640k raw entries and 475k unique domains
(about 3.8 MB of PSRAM) against a `MAX_DOMAINS` cap of 700k. The table is
persisted to LittleFS so a reboot reloads it in under a second.

Refreshes are scheduled from the age of the stored list, not from boot, so a
board that reboots daily still refreshes daily. A failed refresh retries after
10, 20, 40 and 80 minutes, then every 3 hours. If one list fails while others
succeed, the previous complete table stays live for up to two more attempts.

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
- Wi-Fi lost                    -> reconnect with backoff
- Wi-Fi missing at boot         -> setup portal, retrying the saved network every minute
                                   (after a power cut the router is usually just slower to boot)

## Endpoints
Everything needs HTTP Basic Auth. Every POST also needs an `X-AdFree: 1`
header: browsers can't add one cross-origin without a CORS preflight, which
this server never approves, so a page on another site can't use the browser's
cached login to change settings.

| method | path              | purpose                                          |
|--------|-------------------|--------------------------------------------------|
| GET    | /                 | dashboard (gzip, ETag)                           |
| GET    | /api/status       | live counters and health, polled every 3 s       |
| GET    | /api/config       | lists, settings, per-list download results       |
| GET    | /api/history      | 24 h of queries/blocks in 10-minute buckets      |
| GET    | /api/top          | most-blocked domains, busiest devices            |
| GET    | /api/queries      | last 120 lookups with verdicts                   |
| GET    | /api/check?d=     | is this domain blocked, and by which rule        |
| GET    | /api/log          | recent event log                                 |
| POST   | /api/toggle       | `{"enabled": bool}` sets blocking on/off         |
| POST   | /api/pause?secs=  | -1 indefinite, 0 resume, N seconds (max 7 days)  |
| POST   | /api/refresh      | refresh blocklists now                           |
| POST   | /api/domain       | `{"d", "list": "allow"/"deny", "op": "add"/"remove"}` |
| POST   | /api/lists        | replace allowlist / denylist / blocklist URLs    |
| POST   | /api/settings     | upstreams, intervals, updates, LED, static IP    |
| POST   | /api/admin        | change admin login or Wi-Fi credentials          |
| POST   | /api/otacheck     | check the manifest and update if newer           |
| POST   | /api/upload       | manual firmware upload (multipart)               |
| POST   | /api/resetstats   | clear counters, chart and query log              |
| POST   | /api/reboot       | restart                                          |

## OTA
Boards check `ota_manifest_url` (default
`https://sk-0112.github.io/adfree_wifi/firmware/ota.json`) once a day when
automatic updates are on, starting 10 to 60 minutes after boot so a fleet
doesn't hit GitHub at once. The manifest is:

    {"version":"1.1.1","url":"https://host/fw.bin","sha256":"<64 hex chars>"}

Only a numerically newer version installs. Both URLs must be HTTPS, and the
server certificate is verified against the roots in `src/ota_roots.h`
(regenerate with `tools/gen_ota_roots.py`). That check is what makes the
SHA-256 meaningful: without it, whoever could swap the image could swap the
manifest too. The image is streamed into the inactive slot and hashed as it
arrives; a digest mismatch aborts before anything becomes bootable. On reboot a
guard counter arms; the new image must stay healthy (Wi-Fi + DNS) for 60 s or
the device reverts after 3 failed boots.

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
