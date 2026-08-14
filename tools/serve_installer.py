#!/usr/bin/env python3
"""
Serve the web installer locally so it can be tested before the repo goes public.

GitHub Pages doesn't serve private repositories on the free plan, so while
adfree_wifi is private the install page has no public URL. WebSerial needs a
secure context, but it treats http://localhost as one — so this serves docs/ on
localhost and the Install button works exactly as it will in production.

    python tools/serve_installer.py

Then open the printed URL in Chrome, Edge or Opera.
"""

import functools
import http.server
import os
import socketserver
import sys
import webbrowser

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOCS = os.path.join(ROOT, "docs")
PORT = 8000


class Handler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        # The firmware image is rebuilt often during testing; without this the
        # browser happily flashes a stale cached binary.
        self.send_header("Cache-Control", "no-store, max-age=0")
        super().end_headers()

    def log_message(self, fmt, *args):
        sys.stderr.write(f"  {self.address_string()} - {fmt % args}\n")


def main():
    if not os.path.exists(os.path.join(DOCS, "manifest.json")):
        sys.exit("docs/manifest.json is missing. Run:  python tools/build_release.py")

    imgs = [f for f in os.listdir(os.path.join(DOCS, "firmware"))
            if f.endswith(".bin")] if os.path.isdir(os.path.join(DOCS, "firmware")) else []
    if not imgs:
        sys.exit("No firmware image in docs/firmware/. Run:  python tools/build_release.py")

    handler = functools.partial(Handler, directory=DOCS)
    socketserver.TCPServer.allow_reuse_address = True
    port = PORT
    while port < PORT + 20:
        try:
            httpd = socketserver.TCPServer(("127.0.0.1", port), handler)
            break
        except OSError:
            port += 1
    else:
        sys.exit(f"No free port between {PORT} and {PORT + 20}.")

    url = f"http://localhost:{port}/"
    print(f"\n  Serving the installer at  {url}")
    print(f"  Image:                    {imgs[0]}")
    print("\n  Open it in Chrome, Edge or Opera. WebSerial trusts localhost, so")
    print("  the Install button works here exactly as it will once published.")
    print("\n  Ctrl-C to stop.\n")
    try:
        webbrowser.open(url)
    except Exception:
        pass
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n  Stopped.")


if __name__ == "__main__":
    main()
