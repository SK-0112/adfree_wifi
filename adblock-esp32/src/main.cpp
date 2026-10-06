#include <Arduino.h>
#include <WiFi.h>
#include <time.h>
#include <esp_task_wdt.h>
#include <esp_system.h>
#include "config.h"
#include "logger.h"
#include "led_status.h"
#include "wifi_mgr.h"
#include "blocklist.h"
#include "dns_server.h"
#include "web_ui.h"
#include "ota.h"
#include "version.h"

// Compile-time seed credentials. Only used on a truly blank device; once the
// unit has been provisioned, config.json in LittleFS is authoritative and these
// are ignored. Moving to a new house = use the web UI or the setup portal.
//
// Only env:seeded defines ADBLOCK_ALLOW_SEED, so a release build (env:fresh)
// can never accidentally bake in whatever seed_credentials.h happens to be
// sitting in the working tree. Without a seed the board comes up in its
// per-device ADFREE-XXXX hotspot and is provisioned from a phone.
#ifdef ADBLOCK_ALLOW_SEED
#  if defined(__has_include)
#    if __has_include("seed_credentials.h")
#      include "seed_credentials.h"
#    endif
#  endif
#endif

#ifndef SEED_WIFI_SSID
#define SEED_WIFI_SSID ""
#endif
#ifndef SEED_WIFI_PASS
#define SEED_WIFI_PASS ""
#endif
#ifndef SEED_ADMIN_PASS
#define SEED_ADMIN_PASS "adblock123"
#endif

// Generous enough that a long LittleFS write can't trip it, short enough that a
// genuinely wedged loop still recovers quickly.
static const uint32_t WDT_TIMEOUT_S = 90;

static const char *resetReasonStr() {
  switch (esp_reset_reason()) {
    case ESP_RST_POWERON:  return "power-on";
    case ESP_RST_EXT:      return "external pin";
    case ESP_RST_SW:       return "software restart";
    case ESP_RST_PANIC:    return "PANIC / exception";
    case ESP_RST_INT_WDT:  return "interrupt watchdog";
    case ESP_RST_TASK_WDT: return "TASK WATCHDOG";
    case ESP_RST_WDT:      return "other watchdog";
    case ESP_RST_DEEPSLEEP:return "deep sleep wake";
    case ESP_RST_BROWNOUT: return "BROWNOUT (power supply)";
    case ESP_RST_SDIO:     return "sdio";
    default:               return "unknown";
  }
}
static uint32_t s_lastHealthMs = 0;
static uint32_t s_bootMs = 0;
static bool s_dnsUp = false;
static bool s_ntpSynced = false;

static void setupTime() {
  configTime(0, 0, "pool.ntp.org", "time.nist.gov", "time.google.com");
}

static void applyHealthLed() {
  if (!WifiMgr::isConnected()) {
    LedStatus::setState(LedState::ERROR);
    return;
  }
  if (Ota::status().inProgress) {
    LedStatus::setState(LedState::UPDATING);
    return;
  }
  if (!DnsServer53::blockingActive()) {
    LedStatus::setState(LedState::PAUSED);
    return;
  }
  BlocklistStatus bs = Blocklist::status();
  bool stale = false;
  time_t now = time(nullptr);
  if (now > 1700000000 && bs.lastUpdateEpoch) {
    uint32_t maxAge = ConfigStore::cfg.refresh_interval_hours * 3600UL * 3UL;
    stale = (uint32_t)(now - bs.lastUpdateEpoch) > maxAge;
  }
  if (!s_dnsUp || !DnsServer53::upstreamHealthy() || bs.domainCount == 0 || stale) {
    LedStatus::setState(LedState::DEGRADED);
    return;
  }
  LedStatus::setState(LedState::HEALTHY);
}

void setup() {
  Serial.begin(115200);
  delay(400);
  s_bootMs = millis();

  Serial.println();
  Serial.println("=====================================");
  Serial.println("  AdFree " ADFREE_FW_VERSION " - ESP32-S3 DNS ad blocker");
  Serial.println("=====================================");
  Serial.printf("Chip: %s rev%d | flash %u MB | PSRAM %u KB\n", ESP.getChipModel(),
                ESP.getChipRevision(), (unsigned)(ESP.getFlashChipSize() / (1024 * 1024)),
                (unsigned)(ESP.getPsramSize() / 1024));

  LedStatus::begin();
  LedStatus::setState(LedState::BOOTING);

  if (!ConfigStore::begin()) {
    Serial.println("[boot] no stored config; seeding defaults");
  }
  Logger::begin();

  // seed on first boot only
  if (!ConfigStore::cfg.provisioned) {
    if (strlen(SEED_WIFI_SSID)) {
      ConfigStore::cfg.wifi_ssid = SEED_WIFI_SSID;
      ConfigStore::cfg.wifi_pass = SEED_WIFI_PASS;
      ConfigStore::setAdminPassword(SEED_ADMIN_PASS);
      ConfigStore::cfg.provisioned = true;
      ConfigStore::save();
      Logger::log("boot: seeded initial Wi-Fi + admin credentials");
    }
  }

  Logger::log(String("boot: build ") + __DATE__ + " " + __TIME__);
  Logger::log(String("boot: reset reason = ") + resetReasonStr());

  Ota::begin(); // rollback bookkeeping must run before anything can crash

  // Watchdog: if the main loop wedges for 90s the device resets itself. Paired
  // with the OTA boot counter this is what makes a bad image self-recover.
#if ESP_ARDUINO_VERSION_MAJOR >= 3
  esp_task_wdt_config_t wdtCfg = {
      .timeout_ms = WDT_TIMEOUT_S * 1000,
      .idle_core_mask = 0,
      .trigger_panic = true,
  };
  esp_task_wdt_reconfigure(&wdtCfg);
#else
  esp_task_wdt_init(WDT_TIMEOUT_S, true);
#endif
  esp_task_wdt_add(NULL);

  WifiMgr::begin(); // blocks in the setup portal if it can't connect

  setupTime();
  Blocklist::begin();

  s_dnsUp = DnsServer53::begin();
  if (!s_dnsUp) {
    Logger::log("boot: DNS bind FAILED - will retry");
  }

  WebUI::begin();

  Logger::log("boot: ready, ip=" + WiFi.localIP().toString() + " fw=" ADFREE_FW_VERSION);
}

void loop() {
  esp_task_wdt_reset();

#ifdef FORCE_CRASH_TEST
  // Build-time-only fault injection used to verify that OTA rollback actually
  // fires. Never defined in a real build.
  if (millis() > 8000) {
    Serial.println("[crashtest] deliberate abort to exercise rollback");
    Serial.flush();
    abort();
  }
#endif

  WifiMgr::loop();
  WebUI::loop();
  LedStatus::loop();
  Logger::loop();

  if (WifiMgr::isConnected()) {
    if (!s_dnsUp) {
      // retry binding UDP/53 if it failed at boot (e.g. netif wasn't ready)
      static uint32_t lastTry = 0;
      if (millis() - lastTry > 5000) {
        lastTry = millis();
        s_dnsUp = DnsServer53::begin();
        if (s_dnsUp) Logger::log("dns: bound on retry");
      }
    } else {
      DnsServer53::loop();
    }
    Blocklist::loopMaintenance();
    Ota::loop();
  }

  // NTP sync notice (needed for pause timers and timestamps)
  if (!s_ntpSynced && time(nullptr) > 1700000000) {
    s_ntpSynced = true;
    Logger::log("time: NTP synced");
  }

  // expire a finished timed pause so the LED/state return to normal promptly
  if (ConfigStore::cfg.pause_until_epoch && s_ntpSynced &&
      (uint32_t)time(nullptr) >= ConfigStore::cfg.pause_until_epoch) {
    {
      CfgLock g;
      ConfigStore::cfg.pause_until_epoch = 0;
      ConfigStore::save();
    }
    Logger::log("pause: expired, blocking resumed");
  }

  if (millis() - s_lastHealthMs > 1000) {
    s_lastHealthMs = millis();
    applyHealthLed();

    // Once we've been up and healthy for 60s, confirm this firmware is good so
    // the OTA rollback guard disarms.
    if (millis() - s_bootMs > 60000 && WifiMgr::isConnected() && s_dnsUp) {
      Ota::markCurrentImageGood();
    }
  }

  delay(2);
}
