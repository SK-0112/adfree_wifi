#include "web_ui.h"
#include <WiFi.h>
#include <ESPAsyncWebServer.h>
#include <ESPmDNS.h>
#include <ArduinoJson.h>
#include <Update.h>
#include <esp_heap_caps.h>
#include <LittleFS.h>
#include "config.h"
#include "blocklist.h"
#include "dns_server.h"
#include "logger.h"
#include "wifi_mgr.h"
#include "ota.h"
#include "led_status.h"
#include "web_page.h"

static AsyncWebServer s_server(80);
static bool s_mdnsUp = false;

// Every management endpoint requires HTTP Basic Auth against the admin
// credentials in config, so other devices on the LAN can look but not touch.
static bool authed(AsyncWebServerRequest *req) {
  if (ConfigStore::cfg.admin_pass_hash.isEmpty()) return true; // unprovisioned
  if (!req->authenticate(ConfigStore::cfg.admin_user.c_str(), "")) {
    // AsyncWebServer's authenticate() needs the plaintext; we store a hash, so
    // pull the header ourselves and compare hashes instead.
  }
  if (!req->hasHeader("Authorization")) return false;
  String hdr = req->header("Authorization");
  if (!hdr.startsWith("Basic ")) return false;
  String b64 = hdr.substring(6);
  // decode base64
  static const char *T = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  String dec;
  int val = 0, bits = -8;
  for (size_t i = 0; i < b64.length(); i++) {
    const char *p = strchr(T, b64[i]);
    if (!p) continue;
    val = (val << 6) + (int)(p - T);
    bits += 6;
    if (bits >= 0) { dec += (char)((val >> bits) & 0xFF); bits -= 8; }
  }
  int colon = dec.indexOf(':');
  if (colon < 0) return false;
  String u = dec.substring(0, colon);
  String p = dec.substring(colon + 1);
  return u == ConfigStore::cfg.admin_user && ConfigStore::checkAdminPassword(p);
}

static bool guard(AsyncWebServerRequest *req) {
  if (authed(req)) return true;
  AsyncWebServerResponse *r = req->beginResponse(401, "text/plain", "Authentication required");
  r->addHeader("WWW-Authenticate", "Basic realm=\"AdBlock DNS\"");
  req->send(r);
  return false;
}

static void jsonArr(JsonArray a, const std::vector<String> &v) {
  for (auto &s : v) a.add(s);
}
static void arrFrom(JsonArrayConst a, std::vector<String> &v) {
  v.clear();
  for (JsonVariantConst x : a) {
    String s = x.as<String>();
    s.trim();
    s.toLowerCase();
    if (s.length()) v.push_back(s);
  }
}

void WebUI::begin() {
  // ---------------- dashboard ----------------
  s_server.on("/", HTTP_GET, [](AsyncWebServerRequest *req) {
    if (!guard(req)) return;
    AsyncWebServerResponse *r = req->beginResponse(200, "text/html", (const uint8_t *)DASHBOARD_HTML,
                                                   strlen_P(DASHBOARD_HTML));
    r->addHeader("Cache-Control", "no-store");
    req->send(r);
  });

  // ---------------- status json ----------------
  s_server.on("/api/status", HTTP_GET, [](AsyncWebServerRequest *req) {
    if (!guard(req)) return;
    DnsStats st = DnsServer53::stats();
    BlocklistStatus bs = Blocklist::status();
    OtaStatus os = Ota::status();

    JsonDocument d;
    d["blocking"] = DnsServer53::blockingActive();
    bool paused = ConfigStore::cfg.pause_indefinite ||
                  (ConfigStore::cfg.pause_until_epoch &&
                   (uint32_t)time(nullptr) < ConfigStore::cfg.pause_until_epoch);
    d["paused"] = paused;
    long left = 0;
    if (ConfigStore::cfg.pause_indefinite) left = -1;
    else if (ConfigStore::cfg.pause_until_epoch)
      left = (long)ConfigStore::cfg.pause_until_epoch - (long)time(nullptr);
    d["pause_left"] = left;
    d["enabled"] = ConfigStore::cfg.enabled;
    d["hostname"] = ConfigStore::cfg.hostname;
    d["ip"] = WiFi.localIP().toString();
    d["ssid"] = WiFi.SSID();
    // Behind the same Basic Auth as everything else. Shown so the owner can find
    // the fallback hotspot credentials without reflashing or reading serial.
    d["ap_ssid"] = WifiMgr::apSsid();
    d["ap_pass"] = WifiMgr::apPassword();
    d["rssi"] = WiFi.RSSI();
    d["total"] = st.total;
    d["blocked"] = st.blocked;
    d["timeouts"] = st.upstreamTimeouts;
    d["errors"] = st.upstreamErrors;
    d["domains"] = bs.domainCount;
    d["upstream"] = DnsServer53::activeUpstream();
    d["upstream_ok"] = DnsServer53::upstreamHealthy();
    d["bl_ok"] = bs.lastUpdateOk;
    d["bl_err"] = bs.lastError;
    d["bl_refreshing"] = bs.refreshInProgress;
    d["bl_sources_ok"] = bs.sourcesOk;
    d["bl_sources_failed"] = bs.sourcesFailed;
    time_t now = time(nullptr);
    d["bl_age"] = (bs.lastUpdateEpoch && now > 1700000000)
                      ? (long)(now - bs.lastUpdateEpoch) : -1;
    d["heap"] = ESP.getFreeHeap();
    d["psram"] = ESP.getFreePsram();
    d["fs_total"] = LittleFS.totalBytes();
    d["fs_used"] = LittleFS.usedBytes();
    d["uptime"] = millis() / 1000;
    d["fw"] = ConfigStore::cfg.fw_version;
    d["ota_pending"] = os.pendingVerify;
    d["ota_result"] = os.lastResult;
    d["ota_url"] = ConfigStore::cfg.ota_manifest_url;
    d["interval"] = ConfigStore::cfg.refresh_interval_hours;
    d["timeout"] = ConfigStore::cfg.dns_timeout_ms;
    d["led"] = ConfigStore::cfg.led_enabled;
    d["static_enable"] = ConfigStore::cfg.use_static_ip;
    d["static_ip"] = ConfigStore::cfg.static_ip;
    d["static_gw"] = ConfigStore::cfg.static_gw;
    d["static_mask"] = ConfigStore::cfg.static_subnet;
    d["gw"] = WiFi.gatewayIP().toString();
    d["mask"] = WiFi.subnetMask().toString();
    d["mac"] = WiFi.macAddress();
    d["admin_user"] = ConfigStore::cfg.admin_user;

    jsonArr(d["whitelist"].to<JsonArray>(), ConfigStore::cfg.whitelist);
    jsonArr(d["blacklist"].to<JsonArray>(), ConfigStore::cfg.blacklist);
    jsonArr(d["urls"].to<JsonArray>(), ConfigStore::cfg.blocklist_urls);
    jsonArr(d["upstreams"].to<JsonArray>(), ConfigStore::cfg.upstream_dns);

    JsonArray rec = d["recent"].to<JsonArray>();
    for (auto &e : DnsServer53::recentBlocked(25)) {
      JsonObject o = rec.add<JsonObject>();
      o["d"] = e.domain;
      o["c"] = e.client;
      o["a"] = (e.when && now > 1700000000) ? (long)(now - e.when) : 0;
    }
    JsonArray lg = d["log"].to<JsonArray>();
    for (auto &l : Logger::recent(25)) lg.add(l);

    String out;
    serializeJson(d, out);
    AsyncWebServerResponse *r = req->beginResponse(200, "application/json", out);
    r->addHeader("Cache-Control", "no-store");
    req->send(r);
  });

  // ---------------- control ----------------
  s_server.on("/api/toggle", HTTP_POST, [](AsyncWebServerRequest *req) {
    if (!guard(req)) return;
    ConfigStore::cfg.enabled = !ConfigStore::cfg.enabled;
    ConfigStore::cfg.pause_indefinite = false;
    ConfigStore::cfg.pause_until_epoch = 0;
    ConfigStore::save();
    Logger::log(String("ui: blocker ") + (ConfigStore::cfg.enabled ? "ENABLED" : "DISABLED"));
    req->send(200, "text/plain", ConfigStore::cfg.enabled ? "Blocker enabled" : "Blocker disabled");
  });

  s_server.on("/api/pause", HTTP_POST, [](AsyncWebServerRequest *req) {
    if (!guard(req)) return;
    long secs = 0;
    if (req->hasParam("secs")) secs = req->getParam("secs")->value().toInt();
    if (secs < 0) {
      ConfigStore::cfg.pause_indefinite = true;
      ConfigStore::cfg.pause_until_epoch = 0;
      req->send(200, "text/plain", "Paused indefinitely");
    } else if (secs == 0) {
      ConfigStore::cfg.pause_indefinite = false;
      ConfigStore::cfg.pause_until_epoch = 0;
      ConfigStore::cfg.enabled = true;
      req->send(200, "text/plain", "Resumed");
    } else {
      time_t now = time(nullptr);
      if (now < 1700000000) {
        req->send(200, "text/plain", "Clock not synced yet - try again shortly");
        return;
      }
      ConfigStore::cfg.pause_indefinite = false;
      ConfigStore::cfg.pause_until_epoch = (uint32_t)(now + secs);
      req->send(200, "text/plain", "Paused for " + String(secs / 60) + " min");
    }
    ConfigStore::save();
    Logger::log("ui: pause set (" + String(secs) + "s)");
  });

  s_server.on("/api/refresh", HTTP_POST, [](AsyncWebServerRequest *req) {
    if (!guard(req)) return;
    Blocklist::requestRefresh();
    req->send(200, "text/plain", "Blocklist refresh started");
  });

  s_server.on("/api/otacheck", HTTP_POST, [](AsyncWebServerRequest *req) {
    if (!guard(req)) return;
    Ota::requestCheck();
    req->send(200, "text/plain", "Checking for firmware update");
  });

  s_server.on("/api/reboot", HTTP_POST, [](AsyncWebServerRequest *req) {
    if (!guard(req)) return;
    req->send(200, "text/plain", "Rebooting");
    Logger::log("ui: reboot requested");
    delay(300);
    ESP.restart();
  });

  s_server.on("/api/resetstats", HTTP_POST, [](AsyncWebServerRequest *req) {
    if (!guard(req)) return;
    DnsServer53::resetStats();
    req->send(200, "text/plain", "Stats reset");
  });

  // ---------------- lists ----------------
  s_server.on(
      "/api/lists", HTTP_POST, [](AsyncWebServerRequest *req) {}, nullptr,
      [](AsyncWebServerRequest *req, uint8_t *data, size_t len, size_t index, size_t total) {
        if (!guard(req)) return;
        JsonDocument d;
        if (deserializeJson(d, data, len)) {
          req->send(400, "text/plain", "Bad JSON");
          return;
        }
        if (d["whitelist"].is<JsonArray>()) arrFrom(d["whitelist"], ConfigStore::cfg.whitelist);
        if (d["blacklist"].is<JsonArray>()) arrFrom(d["blacklist"], ConfigStore::cfg.blacklist);
        if (d["urls"].is<JsonArray>()) {
          ConfigStore::cfg.blocklist_urls.clear();
          for (JsonVariantConst x : d["urls"].as<JsonArrayConst>()) {
            String s = x.as<String>();
            s.trim();
            if (s.startsWith("http")) ConfigStore::cfg.blocklist_urls.push_back(s);
          }
        }
        ConfigStore::save();
        Blocklist::reloadOverrides();
        Logger::log("ui: lists updated");
        req->send(200, "text/plain", "Lists saved");
      });

  // ---------------- settings ----------------
  s_server.on(
      "/api/settings", HTTP_POST, [](AsyncWebServerRequest *req) {}, nullptr,
      [](AsyncWebServerRequest *req, uint8_t *data, size_t len, size_t index, size_t total) {
        if (!guard(req)) return;
        JsonDocument d;
        if (deserializeJson(d, data, len)) {
          req->send(400, "text/plain", "Bad JSON");
          return;
        }
        if (d["upstreams"].is<JsonArray>()) {
          std::vector<String> ups;
          for (JsonVariantConst x : d["upstreams"].as<JsonArrayConst>()) {
            String s = x.as<String>();
            s.trim();
            IPAddress t;
            if (t.fromString(s)) ups.push_back(s); // only accept valid IPs
          }
          if (!ups.empty()) ConfigStore::cfg.upstream_dns = ups;
        }
        if (d["interval"].is<int>()) {
          int v = d["interval"];
          if (v >= 1 && v <= 720) ConfigStore::cfg.refresh_interval_hours = v;
        }
        if (d["timeout"].is<int>()) {
          int v = d["timeout"];
          if (v >= 200 && v <= 5000) ConfigStore::cfg.dns_timeout_ms = v;
        }
        if (d["ota_url"].is<const char *>()) ConfigStore::cfg.ota_manifest_url = d["ota_url"].as<String>();
        if (d["led"].is<bool>()) ConfigStore::cfg.led_enabled = d["led"];

        // Static IP. Only accepted as a complete, valid set; anything invalid
        // falls back to DHCP so a typo can't strand the device off-network.
        bool netChanged = false;
        if (d["static_enable"].is<bool>()) {
          bool want = d["static_enable"];
          IPAddress a, g, s;
          if (want && a.fromString(d["static_ip"] | "") && g.fromString(d["static_gw"] | "") &&
              s.fromString(d["static_mask"] | "")) {
            ConfigStore::cfg.use_static_ip = true;
            ConfigStore::cfg.static_ip = a.toString();
            ConfigStore::cfg.static_gw = g.toString();
            ConfigStore::cfg.static_subnet = s.toString();
            netChanged = true;
          } else if (!want && ConfigStore::cfg.use_static_ip) {
            ConfigStore::cfg.use_static_ip = false;
            netChanged = true;
          }
        }
        ConfigStore::save();
        Logger::log("ui: settings updated");
        req->send(200, "text/plain",
                  netChanged ? "Settings saved - reboot required for IP change"
                             : "Settings saved");
      });

  // ---------------- admin password / wifi credentials ----------------
  s_server.on(
      "/api/admin", HTTP_POST, [](AsyncWebServerRequest *req) {}, nullptr,
      [](AsyncWebServerRequest *req, uint8_t *data, size_t len, size_t index, size_t total) {
        if (!guard(req)) return;
        JsonDocument d;
        if (deserializeJson(d, data, len)) {
          req->send(400, "text/plain", "Bad JSON");
          return;
        }
        String msg;
        if (d["new_pass"].is<const char *>()) {
          String np = d["new_pass"].as<String>();
          if (np.length() < 8) {
            req->send(400, "text/plain", "Password must be at least 8 characters");
            return;
          }
          ConfigStore::setAdminPassword(np);
          if (d["user"].is<const char *>()) {
            String u = d["user"].as<String>();
            u.trim();
            if (u.length()) ConfigStore::cfg.admin_user = u;
          }
          msg = "Admin credentials updated - log in again";
          Logger::log("ui: admin credentials changed");
        }
        // Changing Wi-Fi is how this device moves to a new house without a PC.
        if (d["wifi_ssid"].is<const char *>()) {
          String ss = d["wifi_ssid"].as<String>();
          ss.trim();
          if (ss.length()) {
            ConfigStore::cfg.wifi_ssid = ss;
            ConfigStore::cfg.wifi_pass = d["wifi_pass"] | "";
            msg = "Wi-Fi saved - reboot to join '" + ss +
                  "'. If it can't connect it will open the '" + WifiMgr::apSsid() +
                  "' setup portal.";
            Logger::log("ui: wifi credentials changed to " + ss);
          }
        }
        if (msg.isEmpty()) {
          req->send(400, "text/plain", "Nothing to change");
          return;
        }
        ConfigStore::save();
        req->send(200, "text/plain", msg);
      });

  // ---------------- manual firmware upload ----------------
  s_server.on(
      "/api/upload", HTTP_POST,
      [](AsyncWebServerRequest *req) {
        bool ok = !Update.hasError();
        AsyncWebServerResponse *r = req->beginResponse(
            ok ? 200 : 500, "text/plain", ok ? "Update OK, rebooting" : "Update FAILED");
        r->addHeader("Connection", "close");
        req->send(r);
        if (ok) { delay(600); ESP.restart(); }
      },
      [](AsyncWebServerRequest *req, String filename, size_t index, uint8_t *data, size_t len,
         bool final) {
        if (!authed(req)) return;
        if (index == 0) Ota::applyUploadedBegin(0);
        Ota::applyUploadedWrite(data, len);
        if (final) Ota::applyUploadedEnd();
      });

  s_server.onNotFound([](AsyncWebServerRequest *req) {
    req->send(404, "text/plain", "Not found");
  });

  s_server.begin();
  Logger::log("web: management UI listening on port 80");
}

void WebUI::loop() {
  if (!s_mdnsUp && WiFi.status() == WL_CONNECTED) {
    if (MDNS.begin(ConfigStore::cfg.hostname.c_str())) {
      MDNS.addService("http", "tcp", 80);
      s_mdnsUp = true;
      Logger::log("web: mDNS up -> http://" + ConfigStore::cfg.hostname + ".local");
    }
  }
  if (s_mdnsUp && WiFi.status() != WL_CONNECTED) {
    s_mdnsUp = false;
  }
}
