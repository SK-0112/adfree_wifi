#include "web_ui.h"
#include <WiFi.h>
#include <ESPAsyncWebServer.h>
#include <ESPmDNS.h>
#include <ArduinoJson.h>
#include <esp_heap_caps.h>
#include <LittleFS.h>
#include <mbedtls/base64.h>
#include "config.h"
#include "blocklist.h"
#include "dns_server.h"
#include "logger.h"
#include "wifi_mgr.h"
#include "ota.h"
#include "version.h"
#include "web_page.h"

static AsyncWebServer s_server(80);
static bool s_mdnsUp = false;
static uint32_t s_rebootAtMs = 0;
static size_t s_fsUsed = 0, s_fsTotal = 0;
static uint32_t s_fsAtMs = 0;

static const size_t MAX_BODY = 16384;
static const size_t MAX_LIST_ENTRIES = 1000;
static const size_t MAX_URLS = 12;

// --------------------------- auth & request guards --------------------------

// Every management endpoint requires HTTP Basic Auth against the admin
// credentials, so other devices on the LAN can look but not touch.
static bool authed(AsyncWebServerRequest *req) {
  String user, hash;
  {
    CfgLock g;
    if (ConfigStore::cfg.admin_pass_hash.isEmpty()) return true; // unprovisioned
    user = ConfigStore::cfg.admin_user;
  }
  const AsyncWebHeader *h = req->getHeader("Authorization");
  if (!h) return false;
  const String &v = h->value();
  if (!v.startsWith("Basic ") || v.length() > 300) return false;
  unsigned char dec[230];
  size_t olen = 0;
  if (mbedtls_base64_decode(dec, sizeof(dec) - 1, &olen, (const unsigned char *)v.c_str() + 6,
                            v.length() - 6) != 0)
    return false;
  dec[olen] = 0;
  char *colon = strchr((char *)dec, ':');
  if (!colon) return false;
  *colon = 0;
  bool ok = user == (const char *)dec && ConfigStore::checkAdminPassword(String(colon + 1));
  memset(dec, 0, sizeof(dec));
  return ok;
}

// The browser sends cached Basic credentials with any request to this host,
// including ones a malicious page on another site makes. A custom header can't
// be added cross-origin without a CORS preflight, which this server never
// approves, so requiring it on every change stops those requests.
static bool sameOrigin(AsyncWebServerRequest *req) {
  return req->hasHeader("X-AdFree");
}

static bool guard(AsyncWebServerRequest *req, bool mutating = false) {
  if (!authed(req)) {
    AsyncWebServerResponse *r = req->beginResponse(401, "text/plain", "Sign in required");
    r->addHeader("WWW-Authenticate", "Basic realm=\"AdFree\"");
    req->send(r);
    return false;
  }
  if (mutating && !sameOrigin(req)) {
    req->send(403, "text/plain", "Request blocked: missing X-AdFree header");
    return false;
  }
  return true;
}

static void sendJson(AsyncWebServerRequest *req, JsonDocument &d, int code = 200) {
  AsyncResponseStream *r = req->beginResponseStream("application/json");
  r->setCode(code);
  r->addHeader("Cache-Control", "no-store");
  serializeJson(d, *r);
  req->send(r);
}

// Collect a request body that may arrive in several TCP segments.
static void collectBody(AsyncWebServerRequest *req, uint8_t *data, size_t len, size_t index, size_t total) {
  if (total > MAX_BODY) return;
  if (index == 0) {
    free(req->_tempObject);
    req->_tempObject = calloc(total + 1, 1);
  }
  if (req->_tempObject && index + len <= total) memcpy((uint8_t *)req->_tempObject + index, data, len);
}

// Parse the collected body. Sends a 4xx and returns false if it's unusable.
static bool parseBody(AsyncWebServerRequest *req, JsonDocument &d, bool optional = false) {
  if (req->contentLength() > MAX_BODY) {
    req->send(413, "text/plain", "Too much data");
    return false;
  }
  if (!req->_tempObject) {
    if (optional) return true;
    req->send(400, "text/plain", "Missing request body");
    return false;
  }
  if (deserializeJson(d, (const char *)req->_tempObject)) {
    req->send(400, "text/plain", "Bad JSON");
    return false;
  }
  return true;
}

static void onJson(const char *path, std::function<void(AsyncWebServerRequest *, JsonDocument &)> fn,
                   bool optionalBody = false) {
  s_server.on(
      path, HTTP_POST,
      [fn, optionalBody](AsyncWebServerRequest *req) {
        if (!guard(req, true)) return;
        JsonDocument d;
        if (!parseBody(req, d, optionalBody)) return;
        fn(req, d);
      },
      nullptr, collectBody);
}

// --------------------------- input cleaning ---------------------------------

// "https://Ads.Example.com/path" or "||ads.example.com^" -> "ads.example.com".
static String cleanDomain(String s) {
  s.trim();
  s.toLowerCase();
  int p = s.indexOf("://");
  if (p >= 0) s = s.substring(p + 3);
  if (s.startsWith("||")) s = s.substring(2);
  if (s.startsWith("*.")) s = s.substring(2);
  for (const char *stop : {"/", "?", "#", ":", "^"}) {
    int i = s.indexOf(stop);
    if (i >= 0) s = s.substring(0, i);
  }
  while (s.endsWith(".")) s.remove(s.length() - 1);
  while (s.startsWith(".")) s.remove(0, 1);
  if (s.length() < 3 || s.length() > 253 || s.indexOf('.') < 0) return String();
  for (char c : s)
    if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_')) return String();
  return s;
}

static void domainsFrom(JsonArrayConst a, std::vector<String> &v) {
  v.clear();
  for (JsonVariantConst x : a) {
    String s = cleanDomain(x.as<String>());
    if (s.length() && std::find(v.begin(), v.end(), s) == v.end()) v.push_back(s);
    if (v.size() >= MAX_LIST_ENTRIES) break;
  }
}

static bool validUpstream(const IPAddress &ip) {
  uint32_t v = (uint32_t)ip;
  return v != 0 && v != 0xFFFFFFFF && ip != WiFi.localIP();
}

static void jsonArr(JsonArray a, const std::vector<String> &v) {
  for (auto &s : v) a.add(s);
}

static long pauseLeft() {
  const AppConfig &c = ConfigStore::cfg;
  if (c.pause_indefinite) return -1;
  if (!c.pause_until_epoch) return 0;
  long left = (long)c.pause_until_epoch - (long)time(nullptr);
  return left > 0 ? left : 0;
}

// ------------------------------------------------------------------------------

void WebUI::begin() {
  DefaultHeaders::Instance().addHeader("X-Content-Type-Options", "nosniff");
  DefaultHeaders::Instance().addHeader("X-Frame-Options", "DENY");
  DefaultHeaders::Instance().addHeader("Referrer-Policy", "no-referrer");

  // ---------------- dashboard ----------------
  s_server.on("/", HTTP_GET, [](AsyncWebServerRequest *req) {
    if (!guard(req)) return;
    const AsyncWebHeader *inm = req->getHeader("If-None-Match");
    if (inm && inm->value() == DASHBOARD_ETAG) {
      AsyncWebServerResponse *r = req->beginResponse(304);
      r->addHeader("ETag", DASHBOARD_ETAG);
      req->send(r);
      return;
    }
    AsyncWebServerResponse *r = req->beginResponse(200, "text/html", DASHBOARD_GZ, DASHBOARD_GZ_LEN);
    r->addHeader("Content-Encoding", "gzip");
    r->addHeader("ETag", DASHBOARD_ETAG);
    r->addHeader("Cache-Control", "no-cache");
    req->send(r);
  });

  // ---------------- live status (polled every few seconds) ----------------
  s_server.on("/api/status", HTTP_GET, [](AsyncWebServerRequest *req) {
    if (!guard(req)) return;
    DnsStats st = DnsServer53::stats();
    BlocklistStatus bs = Blocklist::status();
    OtaStatus os = Ota::status();
    time_t now = time(nullptr);
    bool clock = now > 1700000000;

    JsonDocument d;
    long left = pauseLeft();
    d["enabled"] = ConfigStore::cfg.enabled;
    d["paused"] = ConfigStore::cfg.enabled && left != 0;
    d["pause_left"] = left;
    d["blocking"] = DnsServer53::blockingActive();
    d["host"] = ConfigStore::cfg.hostname;
    d["ip"] = WiFi.localIP().toString();
    d["rssi"] = WiFi.RSSI();
    d["total"] = st.total;
    d["blocked"] = st.blocked;
    d["forwarded"] = st.forwarded;
    d["timeouts"] = st.upstreamTimeouts;
    d["errors"] = st.upstreamErrors;
    d["domains"] = bs.domainCount;
    d["upstream"] = DnsServer53::activeUpstream();
    d["upstream_ok"] = DnsServer53::upstreamHealthy();
    d["clients"] = DnsServer53::activeClients(24 * 3600);
    d["uptime"] = DnsServer53::uptimeSec();
    d["ntp"] = clock;
    d["fw"] = ADFREE_FW_VERSION;
    d["heap"] = ESP.getFreeHeap();
    d["heap_min"] = ESP.getMinFreeHeap();
    d["heap_total"] = ESP.getHeapSize();
    d["psram"] = ESP.getFreePsram();
    d["psram_total"] = ESP.getPsramSize();

    JsonObject bl = d["bl"].to<JsonObject>();
    bl["ok"] = bs.lastUpdateOk;
    bl["err"] = bs.lastError;
    bl["refreshing"] = bs.refreshInProgress;
    bl["age"] = (bs.lastUpdateEpoch > 1700000000 && clock) ? (long)(now - bs.lastUpdateEpoch) : -1;
    bl["next"] = bs.nextRefreshSecs;
    bl["sources_ok"] = bs.sourcesOk;
    bl["sources_failed"] = bs.sourcesFailed;
    bl["cap"] = bs.capacity;

    JsonObject o = d["ota"].to<JsonObject>();
    o["busy"] = os.inProgress;
    o["pct"] = os.percent;
    o["result"] = os.lastResult;
    o["available"] = os.availableVersion;
    o["pending"] = os.pendingVerify;
    o["checked"] = os.lastCheckAgo;
    sendJson(req, d);
  });

  // ---------------- configuration (loaded once per view) ----------------
  s_server.on("/api/config", HTTP_GET, [](AsyncWebServerRequest *req) {
    if (!guard(req)) return;
    BlocklistStatus bs = Blocklist::status();
    JsonDocument d;
    {
      CfgLock g;
      const AppConfig &c = ConfigStore::cfg;
      jsonArr(d["whitelist"].to<JsonArray>(), c.whitelist);
      jsonArr(d["blacklist"].to<JsonArray>(), c.blacklist);
      jsonArr(d["urls"].to<JsonArray>(), c.blocklist_urls);
      jsonArr(d["upstreams"].to<JsonArray>(), c.upstream_dns);
      d["timeout"] = c.dns_timeout_ms;
      d["interval"] = c.refresh_interval_hours;
      d["ota_auto"] = c.ota_auto;
      d["ota_url"] = c.ota_manifest_url;
      d["led"] = c.led_enabled;
      d["static_enable"] = c.use_static_ip;
      d["static_ip"] = c.static_ip;
      d["static_gw"] = c.static_gw;
      d["static_mask"] = c.static_subnet;
      d["admin_user"] = c.admin_user;
      d["ssid"] = c.wifi_ssid;
      d["hostname"] = c.hostname;
    }
    JsonArray src = d["sources"].to<JsonArray>();
    for (auto &s : bs.sources) {
      JsonObject o = src.add<JsonObject>();
      o["url"] = s.url;
      o["ok"] = s.ok;
      o["n"] = s.entries;
      if (s.err.length()) o["err"] = s.err;
    }
    d["ip"] = WiFi.localIP().toString();
    d["gw"] = WiFi.gatewayIP().toString();
    d["mask"] = WiFi.subnetMask().toString();
    d["mac"] = WiFi.macAddress();
    // Shown so the owner can find the fallback hotspot credentials without
    // reflashing; behind the same login as everything else.
    d["ap_ssid"] = WifiMgr::apSsid();
    d["ap_pass"] = WifiMgr::apPassword();
    d["fs_used"] = s_fsUsed;
    d["fs_total"] = s_fsTotal;
    sendJson(req, d);
  });

  // ---------------- activity ----------------
  s_server.on("/api/history", HTTP_GET, [](AsyncWebServerRequest *req) {
    if (!guard(req)) return;
    History h = DnsServer53::history();
    JsonDocument d;
    d["step"] = HISTORY_STEP_S;
    d["age"] = h.ageInBucket;
    JsonArray q = d["q"].to<JsonArray>(), b = d["b"].to<JsonArray>();
    for (size_t i = 0; i < HISTORY_BUCKETS; i++) { q.add(h.q[i]); b.add(h.b[i]); }
    sendJson(req, d);
  });

  s_server.on("/api/top", HTTP_GET, [](AsyncWebServerRequest *req) {
    if (!guard(req)) return;
    JsonDocument d;
    JsonArray dom = d["domains"].to<JsonArray>();
    for (auto &t : DnsServer53::topBlocked(10)) {
      JsonObject o = dom.add<JsonObject>();
      o["d"] = t.domain;
      o["n"] = t.count;
    }
    JsonArray cli = d["clients"].to<JsonArray>();
    for (auto &c : DnsServer53::topClients(10)) {
      JsonObject o = cli.add<JsonObject>();
      o["ip"] = IPAddress(c.ip).toString();
      o["q"] = c.queries;
      o["b"] = c.blocked;
    }
    sendJson(req, d);
  });

  s_server.on("/api/queries", HTTP_GET, [](AsyncWebServerRequest *req) {
    if (!guard(req)) return;
    uint32_t now = DnsServer53::uptimeSec();
    JsonDocument d;
    JsonArray a = d["items"].to<JsonArray>();
    for (auto &e : DnsServer53::recentQueries(120)) {
      JsonObject o = a.add<JsonObject>();
      o["d"] = e.domain;
      o["c"] = IPAddress(e.client).toString();
      o["a"] = now - e.uptime;
      o["t"] = e.qtype;
      o["b"] = (e.verdict == (uint8_t)Verdict::LIST || e.verdict == (uint8_t)Verdict::DENY) ? 1 : 0;
      o["r"] = e.verdict;
    }
    sendJson(req, d);
  });

  s_server.on("/api/check", HTTP_GET, [](AsyncWebServerRequest *req) {
    if (!guard(req)) return;
    String dom = req->hasParam("d") ? cleanDomain(req->getParam("d")->value()) : String();
    if (dom.isEmpty()) {
      req->send(400, "text/plain", "Enter a domain like ads.example.com");
      return;
    }
    size_t off = 0;
    Verdict v = Blocklist::check(dom.c_str(), dom.length(), &off);
    JsonDocument d;
    d["d"] = dom;
    d["blocked"] = v == Verdict::LIST || v == Verdict::DENY;
    d["reason"] = v == Verdict::ALLOW ? "allow" : v == Verdict::DENY ? "deny" : v == Verdict::LIST ? "list" : "none";
    d["match"] = dom.substring(off);
    sendJson(req, d);
  });

  s_server.on("/api/log", HTTP_GET, [](AsyncWebServerRequest *req) {
    if (!guard(req)) return;
    JsonDocument d;
    JsonArray a = d["lines"].to<JsonArray>();
    for (auto &l : Logger::recent(150)) a.add(l);
    sendJson(req, d);
  });

  // ---------------- control ----------------
  onJson(
      "/api/toggle",
      [](AsyncWebServerRequest *req, JsonDocument &d) {
        bool en;
        {
          CfgLock g;
          // The dashboard sends the state it wants, so two open tabs can't
          // flip it back and forth by accident.
          en = d["enabled"].is<bool>() ? d["enabled"].as<bool>() : !ConfigStore::cfg.enabled;
          ConfigStore::cfg.enabled = en;
          ConfigStore::cfg.pause_indefinite = false;
          ConfigStore::cfg.pause_until_epoch = 0;
          ConfigStore::save();
        }
        Logger::log(String("ui: blocking ") + (en ? "ON" : "OFF"));
        req->send(200, "text/plain", en ? "Blocking is on" : "Blocking is off");
      },
      true);

  s_server.on("/api/pause", HTTP_POST, [](AsyncWebServerRequest *req) {
    if (!guard(req, true)) return;
    long secs = req->hasParam("secs") ? req->getParam("secs")->value().toInt() : 0;
    String msg;
    {
      CfgLock g;
      AppConfig &c = ConfigStore::cfg;
      if (secs < 0) {
        c.pause_indefinite = true;
        c.pause_until_epoch = 0;
        msg = "Paused until you resume";
      } else if (secs == 0) {
        c.pause_indefinite = false;
        c.pause_until_epoch = 0;
        c.enabled = true;
        msg = "Blocking resumed";
      } else {
        time_t now = time(nullptr);
        if (now < 1700000000) {
          req->send(503, "text/plain", "The clock isn't set yet. Try again in a moment.");
          return;
        }
        if (secs > 7L * 86400) secs = 7L * 86400;
        c.pause_indefinite = false;
        c.pause_until_epoch = (uint32_t)(now + secs);
        msg = secs >= 3600 ? "Paused for " + String(secs / 3600) + (secs >= 7200 ? " hours" : " hour")
                           : "Paused for " + String(secs / 60) + " minutes";
      }
      ConfigStore::save();
    }
    Logger::log("ui: pause " + String(secs) + "s");
    req->send(200, "text/plain", msg);
  });

  s_server.on("/api/refresh", HTTP_POST, [](AsyncWebServerRequest *req) {
    if (!guard(req, true)) return;
    if (Blocklist::status().refreshInProgress) {
      req->send(409, "text/plain", "An update is already running");
      return;
    }
    if (WiFi.status() != WL_CONNECTED) {
      req->send(503, "text/plain", "No Wi-Fi connection");
      return;
    }
    Blocklist::requestRefresh();
    req->send(200, "text/plain", "Updating blocklists");
  });

  s_server.on("/api/otacheck", HTTP_POST, [](AsyncWebServerRequest *req) {
    if (!guard(req, true)) return;
    if (Ota::busy()) {
      req->send(409, "text/plain", "An update check is already running");
      return;
    }
    Ota::requestCheck();
    req->send(200, "text/plain", "Checking for firmware updates");
  });

  s_server.on("/api/reboot", HTTP_POST, [](AsyncWebServerRequest *req) {
    if (!guard(req, true)) return;
    Logger::log("ui: reboot requested");
    s_rebootAtMs = millis() + 700; // let this response go out first
    req->send(200, "text/plain", "Rebooting");
  });

  s_server.on("/api/resetstats", HTTP_POST, [](AsyncWebServerRequest *req) {
    if (!guard(req, true)) return;
    DnsServer53::resetStats();
    Logger::log("ui: statistics reset");
    req->send(200, "text/plain", "Statistics reset");
  });

  // ---------------- lists ----------------
  onJson("/api/lists", [](AsyncWebServerRequest *req, JsonDocument &d) {
    {
      CfgLock g;
      AppConfig &c = ConfigStore::cfg;
      if (d["whitelist"].is<JsonArray>()) domainsFrom(d["whitelist"], c.whitelist);
      if (d["blacklist"].is<JsonArray>()) domainsFrom(d["blacklist"], c.blacklist);
      if (d["urls"].is<JsonArray>()) {
        std::vector<String> urls;
        for (JsonVariantConst x : d["urls"].as<JsonArrayConst>()) {
          String s = x.as<String>();
          s.trim();
          if ((s.startsWith("https://") || s.startsWith("http://")) && s.length() < 300 &&
              std::find(urls.begin(), urls.end(), s) == urls.end())
            urls.push_back(s);
          if (urls.size() >= MAX_URLS) break;
        }
        c.blocklist_urls = urls;
      }
      ConfigStore::save();
    }
    Blocklist::reloadOverrides();
    Logger::log("ui: lists updated");
    req->send(200, "text/plain", "Lists saved");
  });

  // One domain at a time, for the dashboard's Allow / Block buttons. Adding to
  // one list takes it off the other, so the newest decision always wins.
  onJson("/api/domain", [](AsyncWebServerRequest *req, JsonDocument &d) {
    String dom = cleanDomain(d["d"] | "");
    String list = d["list"] | "";
    String op = d["op"] | "add";
    if (dom.isEmpty() || (list != "allow" && list != "deny")) {
      req->send(400, "text/plain", "Enter a domain like ads.example.com");
      return;
    }
    {
      CfgLock g;
      auto &mine = list == "allow" ? ConfigStore::cfg.whitelist : ConfigStore::cfg.blacklist;
      auto &other = list == "allow" ? ConfigStore::cfg.blacklist : ConfigStore::cfg.whitelist;
      mine.erase(std::remove(mine.begin(), mine.end(), dom), mine.end());
      if (op == "add") {
        if (mine.size() >= MAX_LIST_ENTRIES) {
          req->send(400, "text/plain", "That list is full");
          return;
        }
        mine.push_back(dom);
        other.erase(std::remove(other.begin(), other.end(), dom), other.end());
      }
      ConfigStore::save();
    }
    Blocklist::reloadOverrides();
    Logger::log("ui: " + op + " " + dom + " (" + list + "list)");
    req->send(200, "text/plain", op == "add" ? (list == "allow" ? "Allowed " : "Blocking ") + dom : "Removed " + dom);
  });

  // ---------------- settings ----------------
  onJson("/api/settings", [](AsyncWebServerRequest *req, JsonDocument &d) {
    bool netChanged = false, upsChanged = false;
    String err;
    {
      CfgLock g;
      AppConfig &c = ConfigStore::cfg;
      if (d["upstreams"].is<JsonArray>()) {
        std::vector<String> ups;
        for (JsonVariantConst x : d["upstreams"].as<JsonArrayConst>()) {
          String s = x.as<String>();
          s.trim();
          IPAddress t;
          if (!t.fromString(s) || !validUpstream(t)) {
            err = "Not a usable upstream server: " + s;
            break;
          }
          if (ups.size() < 4) ups.push_back(t.toString());
        }
        if (err.isEmpty() && ups.empty()) err = "Add at least one upstream server";
        if (err.isEmpty()) { c.upstream_dns = ups; upsChanged = true; }
      }
      if (err.isEmpty() && d["interval"].is<int>()) {
        int v = d["interval"];
        if (v >= 1 && v <= 720) c.refresh_interval_hours = v;
        else err = "Refresh interval must be 1 to 720 hours";
      }
      if (err.isEmpty() && d["timeout"].is<int>()) {
        int v = d["timeout"];
        if (v >= 200 && v <= 5000) c.dns_timeout_ms = v;
        else err = "Timeout must be 200 to 5000 ms";
      }
      if (err.isEmpty() && d["ota_url"].is<const char *>()) {
        String u = d["ota_url"].as<String>();
        u.trim();
        if (u.isEmpty()) u = DEFAULT_OTA_MANIFEST;
        if (!u.startsWith("https://")) err = "The update URL must start with https://";
        else c.ota_manifest_url = u;
      }
      if (err.isEmpty() && d["ota_auto"].is<bool>()) c.ota_auto = d["ota_auto"];
      if (err.isEmpty() && d["led"].is<bool>()) c.led_enabled = d["led"];

      if (err.isEmpty() && d["static_enable"].is<bool>()) {
        bool want = d["static_enable"];
        if (want) {
          IPAddress a, gw, s;
          bool ok = a.fromString(d["static_ip"] | "") && gw.fromString(d["static_gw"] | "") &&
                    s.fromString(d["static_mask"] | "");
          uint32_t m = ok ? ntohl((uint32_t)s) : 0;
          ok = ok && m && m != 0xFFFFFFFF && (~m & (~m + 1)) == 0 &&
               ((uint32_t)a & (uint32_t)s) == ((uint32_t)gw & (uint32_t)s) && a != gw;
          if (!ok) err = "The IP address, gateway and mask don't fit together";
          else {
            netChanged = !c.use_static_ip || c.static_ip != a.toString() || c.static_gw != gw.toString() ||
                         c.static_subnet != s.toString();
            c.use_static_ip = true;
            c.static_ip = a.toString();
            c.static_gw = gw.toString();
            c.static_subnet = s.toString();
          }
        } else if (c.use_static_ip) {
          c.use_static_ip = false;
          netChanged = true;
        }
      }
      if (err.isEmpty()) ConfigStore::save();
      else ConfigStore::load(); // drop the half-applied edits
    }
    if (err.length()) {
      req->send(400, "text/plain", err);
      return;
    }
    if (upsChanged) DnsServer53::applyConfig();
    Logger::log("ui: settings updated");
    req->send(200, "text/plain", netChanged ? "Saved. Reboot to use the new address." : "Settings saved");
  });

  // ---------------- admin password / wifi credentials ----------------
  onJson("/api/admin", [](AsyncWebServerRequest *req, JsonDocument &d) {
    String msg;
    bool reboot = false;
    {
      CfgLock g;
      if (d["new_pass"].is<const char *>()) {
        String np = d["new_pass"].as<String>();
        String u = d["user"] | ConfigStore::cfg.admin_user.c_str();
        u.trim();
        if (np.length() < 8 || np.length() > 64) {
          req->send(400, "text/plain", "Use a password of 8 to 64 characters");
          return;
        }
        if (u.isEmpty() || u.indexOf(':') >= 0 || u.length() > 32) {
          req->send(400, "text/plain", "Usernames can't be empty or contain ':'");
          return;
        }
        ConfigStore::setAdminPassword(np);
        ConfigStore::cfg.admin_user = u;
        msg = "Login changed. Sign in again with the new password.";
        Logger::log("ui: admin credentials changed");
      }
      // Changing Wi-Fi is how this device moves to a new house without a PC.
      if (d["wifi_ssid"].is<const char *>()) {
        String ss = d["wifi_ssid"].as<String>();
        String pw = d["wifi_pass"] | "";
        ss.trim();
        if (ss.isEmpty() || ss.length() > 32 || pw.length() > 63 || (pw.length() && pw.length() < 8)) {
          req->send(400, "text/plain", "Check the network name, and use a Wi-Fi password of 8 to 63 characters");
          return;
        }
        ConfigStore::cfg.wifi_ssid = ss;
        ConfigStore::cfg.wifi_pass = pw;
        reboot = d["reboot"] | false;
        msg = "Wi-Fi saved. " + String(reboot ? "Rebooting to join '" : "Reboot to join '") + ss +
              "'. If it can't connect it opens the " + WifiMgr::apSsid() + " hotspot.";
        Logger::log("ui: wifi credentials changed to " + ss);
      }
      if (msg.isEmpty()) {
        req->send(400, "text/plain", "Nothing to change");
        return;
      }
      ConfigStore::save();
    }
    if (reboot) s_rebootAtMs = millis() + 1500;
    req->send(200, "text/plain", msg);
  });

  // ---------------- manual firmware upload ----------------
  s_server.on(
      "/api/upload", HTTP_POST,
      [](AsyncWebServerRequest *req) {
        if (!guard(req, true)) {
          Ota::uploadAbort();
          return;
        }
        bool ok = req->_tempObject && *(bool *)req->_tempObject;
        if (ok) {
          s_rebootAtMs = millis() + 800;
          AsyncWebServerResponse *r = req->beginResponse(200, "text/plain", "Installed. Rebooting...");
          r->addHeader("Connection", "close");
          req->send(r);
        } else {
          OtaStatus os = Ota::status();
          req->send(400, "text/plain", os.lastResult.length() ? os.lastResult : String("Upload failed"));
        }
      },
      [](AsyncWebServerRequest *req, String filename, size_t index, uint8_t *data, size_t len, bool final) {
        if (index == 0) {
          // _tempObject holds "upload succeeded"; only an authenticated,
          // same-origin request may start writing flash.
          free(req->_tempObject);
          req->_tempObject = calloc(1, sizeof(bool) * 2);
          bool *flags = (bool *)req->_tempObject;
          if (!flags || !authed(req) || !sameOrigin(req) || !Ota::uploadBegin()) return;
          flags[1] = true; // began
          req->onDisconnect([]() {
            if (Ota::status().inProgress) Ota::uploadAbort();
          });
        }
        bool *flags = (bool *)req->_tempObject;
        if (!flags || !flags[1]) return;
        if (len && !Ota::uploadWrite(data, len)) { flags[1] = false; return; }
        if (final) flags[0] = Ota::uploadEnd();
      });

  s_server.onNotFound([](AsyncWebServerRequest *req) { req->send(404, "text/plain", "Not found"); });

  s_server.begin();
  Logger::log("web: dashboard on http://" + WiFi.localIP().toString() + "/");
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
    MDNS.end();
    s_mdnsUp = false;
  }
  // Filesystem usage walks every block, so it's sampled here once a minute
  // instead of on each dashboard request, and never during a list write.
  if ((!s_fsAtMs || millis() - s_fsAtMs > 60000)) {
    s_fsAtMs = millis();
    if (Blocklist::status().refreshInProgress) return;
    s_fsTotal = LittleFS.totalBytes();
    s_fsUsed = LittleFS.usedBytes();
  }
  if (s_rebootAtMs && (int32_t)(millis() - s_rebootAtMs) >= 0) {
    Logger::loop();
    ESP.restart();
  }
}
