#include "wifi_mgr.h"
#include <WiFi.h>
#include <DNSServer.h>
#include <WebServer.h>
#include <esp_mac.h>
#include <esp_random.h>
#include <esp_task_wdt.h>
#include "config.h"
#include "led_status.h"
#include "logger.h"

// The setup hotspot's name and password are per device.
//
// The name embeds the last two MAC bytes so two boards in the same house don't
// collide. The password is drawn from the hardware RNG on first boot and kept
// in config.json thereafter.
//
// It deliberately is NOT derived from the MAC: this firmware is open source and
// the MAC is broadcast as the AP's BSSID, so anything computed from it could be
// reproduced by anyone in range. A single compiled-in password would be worse
// still: publishing the source would hand out the key to every board ever
// flashed at once.
static const uint8_t AP_PASS_LEN = 10;

static String s_apSsid;
static String s_apPass;

static void ensureApCredentials() {
  uint8_t mac[6] = {0};
  esp_read_mac(mac, ESP_MAC_WIFI_SOFTAP);
  char suffix[5];
  snprintf(suffix, sizeof(suffix), "%02X%02X", mac[4], mac[5]);
  s_apSsid = String("ADFREE-") + suffix;

  CfgLock g;
  if (ConfigStore::cfg.ap_pass.length() >= 8) {
    s_apPass = ConfigStore::cfg.ap_pass;
    return;
  }

  // Ambiguous glyphs are left out; this gets read off a screen and typed by hand.
  static const char ALPHABET[] = "abcdefghijkmnpqrstuvwxyz23456789";
  const size_t n = sizeof(ALPHABET) - 1;
  String pass;
  pass.reserve(AP_PASS_LEN);
  for (uint8_t i = 0; i < AP_PASS_LEN; i++) pass += ALPHABET[esp_random() % n];

  s_apPass = pass;
  ConfigStore::cfg.ap_pass = pass;
  ConfigStore::save();
  Logger::log("wifi: generated a new setup-hotspot password");
}

static void announceApCredentials() {
  // Printed loudly and repeatedly: for a browser install this serial log is the
  // only place the user can read the password, via the installer's console.
  Serial.println();
  Serial.println("=========================================");
  Serial.println("  SETUP HOTSPOT - join this from a phone");
  Serial.println("=========================================");
  Serial.printf("  Network:   %s\n", s_apSsid.c_str());
  Serial.printf("  Password:  %s\n", s_apPass.c_str());
  Serial.println("  Then open: http://192.168.4.1");
  Serial.println("=========================================");
  Serial.println();
}

String WifiMgr::apSsid() {
  if (s_apSsid.isEmpty()) ensureApCredentials();
  return s_apSsid;
}

String WifiMgr::apPassword() {
  if (s_apPass.isEmpty()) ensureApCredentials();
  return s_apPass;
}

static bool s_portalActive = false;
static bool s_connected = false;
static uint32_t s_lastReconnectAttempt = 0;
static uint8_t s_backoffIdx = 0;
static const uint32_t kBackoffSteps[] = {2000, 5000, 10000, 20000, 60000};

static const char PORTAL_HEAD[] PROGMEM = R"HTML(<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>AdFree setup</title>
<style>
:root{--bg:#0a0c11;--s:#12151d;--l:#2e3446;--f:#eef1f6;--m:#9aa3b5;--a:#4f8cff}
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
background:var(--bg);color:var(--f);font:15px/1.5 -apple-system,"Segoe UI",Roboto,Arial,sans-serif;padding:16px}
form{background:var(--s);border:1px solid var(--l);border-radius:16px;padding:26px;width:100%;max-width:380px}
.b{display:flex;align-items:center;gap:10px;margin-bottom:6px}.b i{width:30px;height:30px;border-radius:9px;
background:linear-gradient(135deg,#4f8cff,#7b5cff)}h1{font-size:19px;margin:0}p{color:var(--m);font-size:13.5px;margin:6px 0 0}
label{display:block;margin:16px 0 6px;font-size:13px;font-weight:600}
input,select{width:100%;height:42px;padding:0 12px;border-radius:10px;border:1px solid var(--l);background:#0d1017;color:var(--f);font-size:15px}
input:focus,select:focus{outline:none;border-color:var(--a)}
button{margin-top:22px;width:100%;height:44px;border:0;border-radius:10px;background:var(--a);color:#fff;font-size:15px;font-weight:600;cursor:pointer}
small{display:block;color:var(--m);font-size:12.5px;margin-top:5px}
</style></head><body>)HTML";

static DNSServer *s_captiveDns = nullptr;
static WebServer *s_portalServer = nullptr;
static String s_scanOptions; // <option> list of nearby networks, built before the AP starts

static String htmlEsc(const String &s) {
  String o;
  o.reserve(s.length() + 8);
  for (char c : s) {
    if (c == '&') o += "&amp;";
    else if (c == '<') o += "&lt;";
    else if (c == '>') o += "&gt;";
    else if (c == '"') o += "&quot;";
    else o += c;
  }
  return o;
}

static String portalPage() {
  bool fallback = ConfigStore::cfg.provisioned && ConfigStore::cfg.admin_pass_hash.length();
  String h = FPSTR(PORTAL_HEAD);
  h += F("<form method='POST' action='/save'><div class='b'><i></i><h1>AdFree setup</h1></div>");
  if (fallback) {
    h += F("<p>AdFree couldn't join <b>");
    h += htmlEsc(ConfigStore::cfg.wifi_ssid);
    h += F("</b>. It keeps retrying in the background. Enter new details below if the network changed.</p>");
  } else {
    h += F("<p>Connect AdFree to your home Wi-Fi.</p>");
  }
  h += F("<label for='s'>Wi-Fi network</label><input id='s' name='ssid' list='nets' required maxlength='32' autocomplete='off' value='");
  h += htmlEsc(ConfigStore::cfg.wifi_ssid);
  h += F("'><datalist id='nets'>");
  h += s_scanOptions;
  h += F("</datalist><label for='p'>Wi-Fi password</label><input id='p' name='pass' type='password' maxlength='63'>");
  h += F("<label for='a'>Admin password for the dashboard</label><input id='a' name='admin' type='password' maxlength='63' minlength='8'");
  h += fallback ? F(" placeholder='Leave blank to keep the current one'>") : F(" required>");
  h += F("<small>At least 8 characters. You'll use it to sign in at http://adblock.local</small>");
  h += F("<button type='submit'>Save and connect</button></form></body></html>");
  return h;
}

bool WifiMgr::isConnected() { return s_connected; }
bool WifiMgr::isPortalActive() { return s_portalActive; }

// Static addressing: accepted only as a coherent set. A typo here would leave
// the board on the network but unreachable, so anything odd falls back to DHCP.
static bool validStatic(IPAddress &ip, IPAddress &gw, IPAddress &sn) {
  if (!ip.fromString(ConfigStore::cfg.static_ip) || !gw.fromString(ConfigStore::cfg.static_gw) ||
      !sn.fromString(ConfigStore::cfg.static_subnet))
    return false;
  uint32_t m = ntohl((uint32_t)sn);
  if (m == 0 || m == 0xFFFFFFFF || (~m & (~m + 1)) != 0) return false; // contiguous mask
  if (((uint32_t)ip & (uint32_t)sn) != ((uint32_t)gw & (uint32_t)sn)) return false;
  return ip != gw;
}

bool WifiMgr::tryConnectSTA(uint32_t timeoutMs) {
  if (ConfigStore::cfg.wifi_ssid.isEmpty()) return false;

  // The hostname only reaches DHCP if it is set before the STA interface starts.
  WiFi.setHostname(ConfigStore::cfg.hostname.c_str());
  WiFi.mode(WIFI_STA);
  WiFi.setSleep(false);

  if (ConfigStore::cfg.use_static_ip) {
    IPAddress ip, gw, sn;
    if (validStatic(ip, gw, sn)) {
      // The board needs a resolver of its own for blocklists, NTP and updates.
      // Without DHCP nothing provides one, so use the configured upstreams.
      IPAddress d1(1, 1, 1, 1), d2(9, 9, 9, 9);
      if (ConfigStore::cfg.upstream_dns.size() > 0) d1.fromString(ConfigStore::cfg.upstream_dns[0]);
      if (ConfigStore::cfg.upstream_dns.size() > 1) d2.fromString(ConfigStore::cfg.upstream_dns[1]);
      WiFi.config(ip, gw, sn, d1, d2);
    } else {
      Logger::log("wifi: static IP settings are inconsistent, using DHCP");
    }
  }

  WiFi.begin(ConfigStore::cfg.wifi_ssid.c_str(), ConfigStore::cfg.wifi_pass.c_str());
  Logger::log("wifi: connecting to " + ConfigStore::cfg.wifi_ssid);

  uint32_t start = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - start < timeoutMs) {
    delay(200);
    esp_task_wdt_reset();
    LedStatus::loop();
  }
  if (WiFi.status() == WL_CONNECTED) {
    s_connected = true;
    WiFi.setAutoReconnect(true);
    Logger::log("wifi: connected, ip=" + WiFi.localIP().toString() + " rssi=" + String(WiFi.RSSI()));
    return true;
  }
  return false;
}

static void scanNearby() {
  WiFi.mode(WIFI_STA);
  int n = WiFi.scanNetworks(false, false);
  s_scanOptions = "";
  for (int i = 0; i < n && i < 20; i++) {
    String s = WiFi.SSID(i);
    if (s.isEmpty() || s_scanOptions.indexOf("\"" + htmlEsc(s) + "\"") >= 0) continue;
    s_scanOptions += "<option value=\"" + htmlEsc(s) + "\">";
  }
  WiFi.scanDelete();
}

void WifiMgr::runPortal() {
  s_portalActive = true;
  LedStatus::setState(LedState::AP_PORTAL);
  scanNearby(); // the radio is up after this, so esp_random() is a true RNG below
  ensureApCredentials();
  bool provisioned = ConfigStore::cfg.provisioned && ConfigStore::cfg.wifi_ssid.length();
  WiFi.mode(provisioned ? WIFI_AP_STA : WIFI_AP);
  WiFi.softAP(s_apSsid.c_str(), s_apPass.c_str());
  IPAddress apIP = WiFi.softAPIP();
  announceApCredentials();
  Logger::log("wifi: portal AP '" + s_apSsid + "' started, ip=" + apIP.toString());

  s_captiveDns = new DNSServer();
  s_captiveDns->start(53, "*", apIP);

  s_portalServer = new WebServer(80);
  auto page = []() {
    s_portalServer->sendHeader("Cache-Control", "no-store");
    s_portalServer->send(200, "text/html", portalPage());
  };
  s_portalServer->onNotFound(page);
  s_portalServer->on("/", HTTP_GET, page);
  s_portalServer->on("/save", HTTP_POST, []() {
    String ssid = s_portalServer->arg("ssid");
    String pass = s_portalServer->arg("pass");
    String admin = s_portalServer->arg("admin");
    ssid.trim();
    bool haveAdmin = ConfigStore::cfg.admin_pass_hash.length() > 0;
    if (ssid.isEmpty() || (admin.length() && admin.length() < 8) || (!haveAdmin && admin.isEmpty())) {
      s_portalServer->send(400, "text/plain", "Enter a network name and an admin password of at least 8 characters.");
      return;
    }
    {
      CfgLock g;
      ConfigStore::cfg.wifi_ssid = ssid;
      ConfigStore::cfg.wifi_pass = pass;
      if (admin.length()) ConfigStore::setAdminPassword(admin);
      // A bad static address is a common reason to end up here. Start clean.
      ConfigStore::cfg.use_static_ip = false;
      ConfigStore::cfg.provisioned = true;
      ConfigStore::save();
    }
    String html = FPSTR(PORTAL_HEAD);
    html += F("<form><div class='b'><i></i><h1>Saved</h1></div><p>AdFree is restarting and joining <b>");
    html += htmlEsc(ssid);
    html += F("</b>. Reconnect this phone to your normal Wi-Fi, then open <b>http://adblock.local</b>.</p></form></body></html>");
    s_portalServer->send(200, "text/html", html);
    uint32_t t = millis();
    while (millis() - t < 1500) { s_portalServer->handleClient(); delay(5); }
    ESP.restart();
  });
  s_portalServer->begin();

  Logger::log("wifi: portal ready, connect to '" + s_apSsid + "' and open http://" + apIP.toString());

  // A provisioned board lands here when its network was unreachable at boot,
  // which after a power cut usually just means the router is still starting.
  // Keep retrying the saved network so the house gets DNS back on its own.
  uint32_t lastAnnounce = millis();
  uint32_t lastTry = millis();
  bool trying = false;
  while (true) {
    esp_task_wdt_reset(); // the watchdog would otherwise reset us every 90 s
    s_captiveDns->processNextRequest();
    s_portalServer->handleClient();
    LedStatus::loop();
    if (millis() - lastAnnounce > 30000) {
      lastAnnounce = millis();
      announceApCredentials();
    }
    if (provisioned) {
      if (!trying && millis() - lastTry > 60000 && WiFi.softAPgetStationNum() == 0) {
        // Nobody is using the portal, so a channel change won't interrupt anyone.
        trying = true;
        lastTry = millis();
        WiFi.begin(ConfigStore::cfg.wifi_ssid.c_str(), ConfigStore::cfg.wifi_pass.c_str());
      } else if (trying && WiFi.status() == WL_CONNECTED) {
        Logger::log("wifi: saved network is back, restarting into normal mode");
        delay(200);
        ESP.restart();
      } else if (trying && millis() - lastTry > 15000) {
        trying = false;
        lastTry = millis();
        WiFi.disconnect(false, false);
      }
    }
    delay(2);
  }
}

bool WifiMgr::begin() {
  LedStatus::setState(LedState::BOOTING);

  if (!ConfigStore::cfg.provisioned || ConfigStore::cfg.wifi_ssid.isEmpty()) {
    Logger::log("wifi: not provisioned, entering setup portal");
    runPortal(); // never returns
    return false;
  }

  // Two attempts before giving up: a router that is just finishing its boot
  // often refuses the first association.
  if (tryConnectSTA(20000) || tryConnectSTA(25000)) return true;

  Logger::log("wifi: can't join " + ConfigStore::cfg.wifi_ssid + ", opening the setup portal (retrying every minute)");
  runPortal(); // never returns
  return false;
}

void WifiMgr::loop() {
  if (s_portalActive) return; // portal has its own blocking loop
  if (WiFi.status() != WL_CONNECTED) {
    if (s_connected) Logger::log("wifi: connection lost");
    s_connected = false;
    uint32_t now = millis();
    uint32_t backoff = kBackoffSteps[min((size_t)s_backoffIdx, (sizeof(kBackoffSteps) / sizeof(kBackoffSteps[0])) - 1)];
    if (now - s_lastReconnectAttempt > backoff) {
      s_lastReconnectAttempt = now;
      Logger::log("wifi: reconnect attempt");
      WiFi.disconnect();
      WiFi.reconnect();
      if (s_backoffIdx < 4) s_backoffIdx++;
    }
  } else {
    if (!s_connected) Logger::log("wifi: reconnected, ip=" + WiFi.localIP().toString());
    s_connected = true;
    s_backoffIdx = 0;
  }
}
