#include "wifi_mgr.h"
#include <WiFi.h>
#include <DNSServer.h>
#include <WebServer.h>
#include <esp_mac.h>
#include <esp_random.h>
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
// still — publishing the source would hand out the key to every board ever
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

static const char PORTAL_HTML[] PROGMEM = R"HTML(
<!DOCTYPE html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AdBlock Setup</title>
<style>
body{font-family:-apple-system,Segoe UI,Arial,sans-serif;background:#111;color:#eee;
     display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
form{background:#1c1c1c;padding:2em;border-radius:12px;width:320px;max-width:90vw}
h1{font-size:1.2em;margin-top:0}
label{display:block;margin:0.8em 0 0.2em;font-size:0.9em;color:#aaa}
input{width:100%;box-sizing:border-box;padding:0.6em;border-radius:6px;border:1px solid #444;
      background:#0d0d0d;color:#eee;font-size:1em}
button{margin-top:1.4em;width:100%;padding:0.7em;border:0;border-radius:6px;
       background:#3b82f6;color:#fff;font-size:1em;cursor:pointer}
p.hint{color:#888;font-size:0.8em}
</style></head><body>
<form method="POST" action="/save">
<h1>AdBlock DNS &mdash; Wi-Fi Setup</h1>
<label>Wi-Fi Network Name (SSID)</label>
<input name="ssid" required maxlength="63">
<label>Wi-Fi Password</label>
<input name="pass" type="password" maxlength="63">
<label>Admin Password (for the device's management page)</label>
<input name="admin" type="password" required minlength="6" maxlength="63">
<p class="hint">The device will reboot and join your network. Reconnect to your
normal Wi-Fi, then find it at http://adblock.local</p>
<button type="submit">Save &amp; Connect</button>
</form></body></html>
)HTML";

static DNSServer *s_captiveDns = nullptr;
static WebServer *s_portalServer = nullptr;

bool WifiMgr::isConnected() { return s_connected; }
bool WifiMgr::isPortalActive() { return s_portalActive; }

bool WifiMgr::tryConnectSTA(uint32_t timeoutMs) {
  if (ConfigStore::cfg.wifi_ssid.isEmpty()) return false;

  WiFi.mode(WIFI_STA);
  WiFi.setSleep(false);
  String host = ConfigStore::cfg.hostname;
  WiFi.setHostname(host.c_str());

  if (ConfigStore::cfg.use_static_ip && ConfigStore::cfg.static_ip.length()) {
    IPAddress ip, gw, sn;
    ip.fromString(ConfigStore::cfg.static_ip);
    gw.fromString(ConfigStore::cfg.static_gw);
    sn.fromString(ConfigStore::cfg.static_subnet);
    WiFi.config(ip, gw, sn);
  }

  WiFi.begin(ConfigStore::cfg.wifi_ssid.c_str(), ConfigStore::cfg.wifi_pass.c_str());
  Logger::log("wifi: connecting to " + ConfigStore::cfg.wifi_ssid);

  uint32_t start = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - start < timeoutMs) {
    delay(200);
    LedStatus::loop();
  }
  if (WiFi.status() == WL_CONNECTED) {
    s_connected = true;
    WiFi.setAutoReconnect(true);
    Logger::log("wifi: connected, ip=" + WiFi.localIP().toString());
    return true;
  }
  return false;
}

void WifiMgr::runPortal() {
  s_portalActive = true;
  LedStatus::setState(LedState::AP_PORTAL);
  // Bring the radio up first: esp_random() is only a true RNG once RF is running.
  WiFi.mode(WIFI_AP);
  ensureApCredentials();
  WiFi.softAP(s_apSsid.c_str(), s_apPass.c_str());
  IPAddress apIP = WiFi.softAPIP();
  announceApCredentials();
  Logger::log("wifi: portal AP '" + s_apSsid + "' started, ip=" + apIP.toString());

  s_captiveDns = new DNSServer();
  s_captiveDns->start(53, "*", apIP);

  s_portalServer = new WebServer(80);
  s_portalServer->onNotFound([]() {
    s_portalServer->send(200, "text/html", PORTAL_HTML);
  });
  s_portalServer->on("/", HTTP_GET, []() {
    s_portalServer->send(200, "text/html", PORTAL_HTML);
  });
  s_portalServer->on("/save", HTTP_POST, []() {
    String ssid = s_portalServer->arg("ssid");
    String pass = s_portalServer->arg("pass");
    String admin = s_portalServer->arg("admin");
    if (ssid.isEmpty() || admin.length() < 6) {
      s_portalServer->send(400, "text/plain", "Missing SSID or admin password too short");
      return;
    }
    ConfigStore::cfg.wifi_ssid = ssid;
    ConfigStore::cfg.wifi_pass = pass;
    ConfigStore::setAdminPassword(admin);
    ConfigStore::cfg.provisioned = true;
    ConfigStore::save();
    s_portalServer->send(200, "text/html",
        "<html><body style='font-family:sans-serif;background:#111;color:#eee;"
        "text-align:center;padding-top:3em'><h2>Saved. Rebooting&hellip;</h2>"
        "<p>Reconnect to your normal Wi-Fi and visit http://adblock.local</p></body></html>");
    delay(1500);
    ESP.restart();
  });
  s_portalServer->begin();

  Logger::log("wifi: portal ready, connect to '" + s_apSsid + "' and open http://" +
              apIP.toString());

  uint32_t lastAnnounce = millis();
  while (true) {
    s_captiveDns->processNextRequest();
    s_portalServer->handleClient();
    LedStatus::loop();
    // Repeat the credentials so they're visible whenever the console is opened,
    // not just to whoever happened to be watching at boot.
    if (millis() - lastAnnounce > 30000) {
      lastAnnounce = millis();
      announceApCredentials();
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

  if (tryConnectSTA(20000)) {
    return true;
  }

  Logger::log("wifi: initial connect failed, entering setup portal as fallback");
  runPortal(); // never returns
  return false;
}

void WifiMgr::loop() {
  if (s_portalActive) return; // portal has its own blocking loop
  if (WiFi.status() != WL_CONNECTED) {
    if (s_connected) {
      Logger::log("wifi: connection lost");
    }
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
    if (!s_connected) {
      Logger::log("wifi: reconnected, ip=" + WiFi.localIP().toString());
    }
    s_connected = true;
    s_backoffIdx = 0;
  }
}
