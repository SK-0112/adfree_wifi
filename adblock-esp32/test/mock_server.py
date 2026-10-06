#!/usr/bin/env python3
"""
Serve web/index.html against a fake AdFree API, for working on the dashboard
without a board.

    python adblock-esp32/test/mock_server.py      ->  http://localhost:8080

All data is synthetic. State changes (pause, lists, settings) are kept in
memory so the UI behaves as it would on the device.
"""
import json
import os
import random
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
PAGE = os.path.join(HERE, "..", "web", "index.html")
START = time.time()

AD = ["doubleclick.net", "googleads.g.doubleclick.net", "app-measurement.com", "graph.facebook.com",
      "ads.yahoo.com", "pagead2.googlesyndication.com", "settings-win.data.microsoft.com",
      "mobile.events.data.microsoft.com", "browser.sentry-cdn.com", "cdn.taboola.com", "scorecardresearch.com",
      "samsungads.com", "log.byteoversea.com", "unagi.amazon.com", "mask.icloud.com"]
OK = ["www.google.com", "i.ytimg.com", "api.github.com", "www.netflix.com", "fonts.gstatic.com",
      "rr3---sn-ab5l6n7s.googlevideo.com", "gateway.icloud.com", "www.bbc.co.uk", "teams.microsoft.com",
      "open.spotify.com", "cdn.discordapp.com", "www.instagram.com", "time.apple.com"]
CLIENTS = ["192.168.0.173", "192.168.0.36", "192.168.0.122", "192.168.0.144", "192.168.0.205", "192.168.0.11"]

S = {
    "enabled": True, "pause_until": 0, "pause_indef": False,
    "whitelist": ["login.microsoftonline.com"], "blacklist": ["ads.example.com"],
    "urls": ["https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.plus.txt",
             "https://big.oisd.nl/",
             "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt"],
    "upstreams": ["1.1.1.1", "9.9.9.9", "1.0.0.1"], "timeout": 1200, "interval": 24,
    "ota_auto": True, "ota_url": "https://sk-0112.github.io/adfree_wifi/firmware/ota.json", "led": True,
    "static": False, "refreshing_until": 0, "total": 184_532, "blocked": 41_210,
}
HQ = [max(0, int(260 + 200 * __import__("math").sin(i / 22) + random.randint(-40, 60))) for i in range(144)]
HB = [int(q * random.uniform(.15, .3)) for q in HQ]
QUERIES = []


def tick():
    for _ in range(random.randint(1, 4)):
        blocked = random.random() < .25
        d = random.choice(AD if blocked else OK)
        if d in S["whitelist"]:
            blocked = False
        if d in S["blacklist"]:
            blocked = True
        QUERIES.insert(0, {"d": d, "c": random.choice(CLIENTS), "t": random.choice([1, 1, 1, 28, 65]),
                           "at": time.time(), "b": 1 if blocked else 0,
                           "r": (1 if blocked else (3 if d in S["whitelist"] else 0))})
        S["total"] += 1
        S["blocked"] += blocked
    del QUERIES[120:]


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def send(self, code, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else (json.dumps(body) if ctype == "application/json" else body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        u = urlparse(self.path)
        p = u.path
        now = time.time()
        tick()
        if p == "/":
            return self.send(200, open(PAGE, "rb").read(), "text/html")
        if p == "/api/status":
            left = -1 if S["pause_indef"] else max(0, int(S["pause_until"] - now))
            ref = S["refreshing_until"] > now
            return self.send(200, {
                "enabled": S["enabled"], "paused": S["enabled"] and left != 0, "pause_left": left,
                "blocking": S["enabled"] and left == 0, "host": "adblock", "ip": "192.168.0.95", "rssi": -58,
                "total": S["total"], "blocked": S["blocked"], "forwarded": S["total"] - S["blocked"],
                "timeouts": 12, "errors": 0, "domains": 471_452, "upstream": S["upstreams"][0], "upstream_ok": True,
                "clients": len(CLIENTS), "uptime": int(now - START) + 3 * 86400 + 4100, "ntp": True, "fw": "1.1.0",
                "heap": 182_000, "heap_min": 141_000, "heap_total": 327_680, "psram": 3_900_000,
                "psram_total": 8_388_608,
                "bl": {"ok": True, "err": "", "refreshing": ref, "age": 3 * 3600 + 120, "next": 21 * 3600,
                       "sources_ok": 3, "sources_failed": 0, "cap": 700_000},
                "ota": {"busy": False, "pct": 0, "result": "up to date (1.1.0)", "available": "1.1.0",
                        "pending": False, "checked": 4000}})
        if p == "/api/config":
            return self.send(200, {
                "whitelist": S["whitelist"], "blacklist": S["blacklist"], "urls": S["urls"],
                "upstreams": S["upstreams"], "timeout": S["timeout"], "interval": S["interval"],
                "ota_auto": S["ota_auto"], "ota_url": S["ota_url"], "led": S["led"],
                "static_enable": S["static"], "static_ip": "", "static_gw": "", "static_mask": "",
                "admin_user": "admin", "ssid": "HomeWiFi", "hostname": "adblock",
                "sources": [{"url": S["urls"][0], "ok": True, "n": 221_621},
                            {"url": S["urls"][1], "ok": True, "n": 240_507},
                            {"url": S["urls"][2], "ok": False, "n": 0, "err": "HTTP 503"}] if len(S["urls"]) >= 3 else [],
                "ip": "192.168.0.95", "gw": "192.168.0.1", "mask": "255.255.255.0", "mac": "F4:12:FA:00:11:22",
                "ap_ssid": "ADFREE-1122", "ap_pass": "k7m2xq9fhp", "fs_used": 4_300_000, "fs_total": 10_289_152})
        if p == "/api/history":
            return self.send(200, {"step": 600, "age": int(now) % 600, "q": HQ, "b": HB})
        if p == "/api/top":
            return self.send(200, {
                "domains": [{"d": d, "n": int(9000 / (i + 1))} for i, d in enumerate(AD[:10])],
                "clients": [{"ip": c, "q": int(60000 / (i + 1)), "b": int(14000 / (i + 1.5))} for i, c in enumerate(CLIENTS)]})
        if p == "/api/queries":
            return self.send(200, {"items": [dict(q, a=int(now - q["at"])) for q in QUERIES]})
        if p == "/api/check":
            d = parse_qs(u.query).get("d", [""])[0]
            if d in S["whitelist"]:
                return self.send(200, {"d": d, "blocked": False, "reason": "allow", "match": d})
            if d in S["blacklist"]:
                return self.send(200, {"d": d, "blocked": True, "reason": "deny", "match": d})
            hit = next((a for a in AD if d == a or d.endswith("." + a)), None)
            return self.send(200, {"d": d, "blocked": bool(hit), "reason": "list" if hit else "none", "match": hit or d})
        if p == "/api/log":
            return self.send(200, {"lines": [f"[3d 01:{i:02d}:00] bl: fetching list {i}" for i in range(30)]})
        return self.send(404, "Not found", "text/plain")

    def do_POST(self):
        if "X-AdFree" not in self.headers:
            return self.send(403, "Request blocked: missing X-AdFree header", "text/plain")
        u = urlparse(self.path)
        p = u.path
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n) if n else b""
        try:
            d = json.loads(body) if body and "json" in (self.headers.get("Content-Type") or "") else {}
        except ValueError:
            return self.send(400, "Bad JSON", "text/plain")
        if p == "/api/toggle":
            S["enabled"] = d.get("enabled", not S["enabled"])
            S["pause_until"] = 0
            S["pause_indef"] = False
            return self.send(200, "Blocking is on" if S["enabled"] else "Blocking is off", "text/plain")
        if p == "/api/pause":
            secs = int(parse_qs(u.query).get("secs", ["0"])[0])
            S["pause_indef"] = secs < 0
            S["pause_until"] = time.time() + secs if secs > 0 else 0
            if secs == 0:
                S["enabled"] = True
            return self.send(200, "Blocking resumed" if secs == 0 else "Paused", "text/plain")
        if p == "/api/refresh":
            S["refreshing_until"] = time.time() + 12
            return self.send(200, "Updating blocklists", "text/plain")
        if p == "/api/domain":
            dom, lst, op = d.get("d", ""), d.get("list"), d.get("op", "add")
            mine = S["whitelist"] if lst == "allow" else S["blacklist"]
            other = S["blacklist"] if lst == "allow" else S["whitelist"]
            if dom in mine:
                mine.remove(dom)
            if op == "add":
                mine.append(dom)
                if dom in other:
                    other.remove(dom)
            return self.send(200, ("Allowed " if lst == "allow" else "Blocking ") + dom, "text/plain")
        if p == "/api/lists":
            for k in ("whitelist", "blacklist", "urls"):
                if k in d:
                    S[k] = d[k]
            return self.send(200, "Lists saved", "text/plain")
        if p == "/api/settings":
            for k, sk in (("upstreams", "upstreams"), ("timeout", "timeout"), ("interval", "interval"),
                          ("ota_auto", "ota_auto"), ("ota_url", "ota_url"), ("led", "led"), ("static_enable", "static")):
                if k in d:
                    S[sk] = d[k]
            return self.send(200, "Settings saved", "text/plain")
        if p in ("/api/admin", "/api/otacheck", "/api/reboot", "/api/resetstats", "/api/upload"):
            return self.send(200, "OK", "text/plain")
        return self.send(404, "Not found", "text/plain")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    print(f"mock AdFree on http://localhost:{port}")
    ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()
