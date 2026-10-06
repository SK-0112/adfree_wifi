"""
PlatformIO pre-build step: gzip web/index.html into src/web_page.h.

The dashboard is edited as a normal HTML file and served pre-compressed, which
cuts what the board sends per page load to roughly a quarter and lets the
browser revalidate it with an ETag instead of downloading it again.

Runs automatically from platformio.ini (extra_scripts = pre:scripts/embed_web.py)
and can also be run by hand: python scripts/embed_web.py
"""
import gzip
import hashlib
import os

try:
    Import("env")  # noqa: F821  (provided by PlatformIO)
    PROJECT = env["PROJECT_DIR"]  # noqa: F821
except NameError:
    PROJECT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SRC = os.path.join(PROJECT, "web", "index.html")
OUT = os.path.join(PROJECT, "src", "web_page.h")


def main():
    with open(SRC, "rb") as f:
        html = f.read()
    # mtime=0 keeps the output byte-identical between builds, so the header
    # (and the firmware) only changes when the page does.
    gz = gzip.compress(html, compresslevel=9, mtime=0)
    etag = hashlib.sha1(html).hexdigest()[:16]
    lines = []
    for i in range(0, len(gz), 20):
        lines.append("  " + ",".join(f"0x{b:02x}" for b in gz[i:i + 20]) + ",")
    body = (
        "#pragma once\n"
        "// Generated from web/index.html by scripts/embed_web.py - edit the HTML, not this.\n"
        "#include <Arduino.h>\n\n"
        f'static const char DASHBOARD_ETAG[] = "\\"{etag}\\"";\n'
        f"static const size_t DASHBOARD_GZ_LEN = {len(gz)};\n"
        "static const uint8_t DASHBOARD_GZ[] PROGMEM = {\n" + "\n".join(lines) + "\n};\n"
    )
    old = None
    if os.path.exists(OUT):
        with open(OUT, encoding="utf-8") as f:
            old = f.read()
    if old != body:
        with open(OUT, "w", encoding="utf-8", newline="\n") as f:
            f.write(body)
    print(f"embed_web: {len(html)} bytes -> {len(gz)} gzipped ({etag})")


main()
