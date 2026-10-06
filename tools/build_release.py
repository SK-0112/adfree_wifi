#!/usr/bin/env python3
"""
Build a publishable AdFree image.

Compiles env:fresh (which can never contain Wi-Fi credentials), merges the
bootloader / partition table / boot selector / application into one flat image
that can be written at offset 0, and drops it into docs/firmware/ alongside the
manifest the web installer reads.

    python tools/build_release.py

The result is what GitHub Releases and https://<user>.github.io/<repo>/ serve.
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FW_DIR = os.path.join(ROOT, "adblock-esp32")
BUILD_DIR = os.path.join(FW_DIR, ".pio", "build", "fresh")
OUT_DIR = os.path.join(ROOT, "docs", "firmware")
MANIFEST = os.path.join(ROOT, "docs", "manifest.json")
OTA_MANIFEST = os.path.join(OUT_DIR, "ota.json")
# Where GitHub Pages serves docs/. Boards fetch firmware/ota.json from here.
PAGES_URL = "https://sk-0112.github.io/adfree_wifi"

# Offsets for an Arduino-ESP32 dual-OTA layout on the ESP32-S3.
BOOTLOADER_OFFSET = 0x0
PARTITIONS_OFFSET = 0x8000
BOOT_APP0_OFFSET = 0xE000
APP_OFFSET = 0x10000


def run(cmd, **kw):
    print("$ " + " ".join(cmd))
    subprocess.run(cmd, check=True, **kw)


def firmware_version():
    """Single source of truth for the version: ADFREE_FW_VERSION in version.h."""
    with open(os.path.join(FW_DIR, "src", "version.h"), encoding="utf-8") as f:
        m = re.search(r'#define\s+ADFREE_FW_VERSION\s+"([^"]+)"', f.read())
    if not m:
        sys.exit("Could not find ADFREE_FW_VERSION in src/version.h")
    return m.group(1)


def find_boot_app0():
    """boot_app0.bin ships with the Arduino core, not with this project."""
    base = os.path.join(os.path.expanduser("~"), ".platformio", "packages",
                        "framework-arduinoespressif32", "tools", "partitions")
    path = os.path.join(base, "boot_app0.bin")
    if not os.path.exists(path):
        sys.exit(f"boot_app0.bin not found at {path}\n"
                 "Build the firmware once with PlatformIO first.")
    return path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-build", action="store_true",
                    help="reuse the existing .pio/build/fresh artifacts")
    args = ap.parse_args()

    version = firmware_version()
    print(f"AdFree {version}\n")

    if not args.skip_build:
        # A stale env:fresh tree could still hold objects compiled back when the
        # seed header was being included, so start from clean.
        run([sys.executable, "-m", "platformio", "run", "-e", "fresh", "-t", "clean"], cwd=FW_DIR)
        run([sys.executable, "-m", "platformio", "run", "-e", "fresh"], cwd=FW_DIR)

    app = os.path.join(BUILD_DIR, "firmware.bin")
    for path in (app, os.path.join(BUILD_DIR, "bootloader.bin"),
                 os.path.join(BUILD_DIR, "partitions.bin")):
        if not os.path.exists(path):
            sys.exit(f"Missing build artifact: {path}")

    # Guard rail: the release image must not carry anyone's credentials. The
    # seed strings would appear verbatim in .rodata if they had been compiled in.
    with open(app, "rb") as f:
        blob = f.read()
    seed_header = os.path.join(FW_DIR, "src", "seed_credentials.h")
    if os.path.exists(seed_header):
        with open(seed_header, encoding="utf-8") as f:
            leaked = [v for v in re.findall(r'"((?:[^"\\]|\\.)+)"', f.read())
                      if len(v) >= 6 and v.encode() in blob]
        if leaked:
            sys.exit("REFUSING TO PUBLISH: the built image contains strings from "
                     "src/seed_credentials.h. Build env:fresh, not env:seeded.")

    os.makedirs(OUT_DIR, exist_ok=True)
    merged_name = f"adfree-esp32s3-{version}.bin"
    merged = os.path.join(OUT_DIR, merged_name)

    # "keep" everywhere is deliberate. merge-bin rewrites the bootloader's header
    # from these flags, and passing an explicit mode silently overrides whatever
    # the toolchain built. Forcing qio here produced an image whose bootloader
    # claimed QIO while the board could only boot DIO: the ROM loader failed and
    # the board sat in a TG0WDT reset loop, with nothing on the serial console
    # but ets_loader.c. The build already stamps the correct values, so the merge
    # step must not have an opinion.
    run([sys.executable, "-m", "esptool", "--chip", "esp32s3", "merge-bin",
         "-o", merged,
         "--flash-mode", "keep", "--flash-freq", "keep", "--flash-size", "keep",
         hex(BOOTLOADER_OFFSET), os.path.join(BUILD_DIR, "bootloader.bin"),
         hex(PARTITIONS_OFFSET), os.path.join(BUILD_DIR, "partitions.bin"),
         hex(BOOT_APP0_OFFSET), find_boot_app0(),
         hex(APP_OFFSET), app])

    # The single byte that caused that failure. Cheap to assert, and a silent
    # regression here bricks every board the image is flashed onto.
    with open(os.path.join(BUILD_DIR, "bootloader.bin"), "rb") as f:
        built_hdr = f.read(4)
    with open(merged, "rb") as f:
        merged_hdr = f.read(4)
    if built_hdr != merged_hdr:
        sys.exit(f"Bootloader header was altered by the merge: "
                 f"built {built_hdr.hex()} -> merged {merged_hdr.hex()}. "
                 f"Flash mode/size/freq must be passed through unchanged.")

    with open(merged, "rb") as f:
        data = f.read()
    digest = hashlib.sha256(data).hexdigest()

    # The app-only image is what boards download for an over-the-air update;
    # the merged image above is only for a fresh USB install.
    app_name = f"adfree-esp32s3-app-{version}.bin"
    shutil.copyfile(app, os.path.join(OUT_DIR, app_name))
    with open(app, "rb") as f:
        app_digest = hashlib.sha256(f.read()).hexdigest()

    # Keep only the current images so Pages doesn't accumulate old builds.
    for old in os.listdir(OUT_DIR):
        if old.startswith("adfree-esp32s3-") and old not in (merged_name, app_name):
            os.remove(os.path.join(OUT_DIR, old))

    with open(OTA_MANIFEST, "w", encoding="utf-8") as f:
        json.dump({
            "version": version,
            "url": f"{PAGES_URL}/firmware/{app_name}",
            "sha256": app_digest,
        }, f, indent=2)
        f.write("\n")

    with open(MANIFEST, "w", encoding="utf-8") as f:
        json.dump({
            "name": "AdFree DNS Blocker",
            "version": version,
            "new_install_prompt_erase": True,
            "builds": [{
                "chipFamily": "ESP32-S3",
                "parts": [{"path": f"firmware/{merged_name}", "offset": 0}],
            }],
        }, f, indent=2)
        f.write("\n")

    print(f"\n  image     docs/firmware/{merged_name}")
    print(f"  size      {len(data) / 1024:.0f} KB")
    print(f"  sha256    {digest}")
    print(f"  ota       docs/firmware/{app_name}  ({app_digest[:16]}...)")
    print("\nCommit docs/ and the web installer serves this build.")


if __name__ == "__main__":
    main()
