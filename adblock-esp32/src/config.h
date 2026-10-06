#pragma once
#include <Arduino.h>
#include <vector>
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>

#define DEFAULT_OTA_MANIFEST "https://sk-0112.github.io/adfree_wifi/firmware/ota.json"

struct AppConfig {
  // network
  String wifi_ssid;
  String wifi_pass;
  bool use_static_ip = false;
  String static_ip, static_gw, static_subnet;

  // hostname
  String hostname = "adblock";

  // admin auth (HTTP Basic Auth on management UI / API / OTA)
  String admin_user = "admin";
  String admin_pass_hash; // sha256 hex of password

  // Setup-portal hotspot password. Generated per device from the hardware RNG on
  // first boot rather than compiled in: the firmware is open source, so any
  // baked-in password would be public, and one shared across every board would
  // let anyone in range hijack an unprovisioned unit. Stored in clear because
  // WPA2 needs the plaintext to bring the AP up.
  String ap_pass;

  // dns
  std::vector<String> upstream_dns = {"1.1.1.1", "9.9.9.9", "1.0.0.1"};
  uint16_t dns_timeout_ms = 1200;

  // blocklist - these defaults match the tuned production set, so a freshly
  // flashed board comes up with the same coverage without any manual setup
  std::vector<String> blocklist_urls = {
      "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.plus.txt",
      "https://big.oisd.nl/",
      "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt",
      // Blocks DNS-over-HTTPS resolvers and iCloud Private Relay, which
      // otherwise let browsers and phones skip this device entirely.
      "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/doh.txt"};
  uint32_t refresh_interval_hours = 24;
  std::vector<String> whitelist;
  std::vector<String> blacklist;

  // control
  bool enabled = true;
  uint32_t pause_until_epoch = 0; // 0 = not paused
  bool pause_indefinite = false;

  // ota. The running version is ADFREE_FW_VERSION in version.h, not config.
  String ota_manifest_url = DEFAULT_OTA_MANIFEST;
  bool ota_auto = true; // check daily and install verified updates

  // led
  bool led_enabled = true;

  // internal / first-boot marker
  bool provisioned = false;
};

class ConfigStore {
public:
  // cfg is written from web handlers (AsyncTCP task) and read from the main
  // loop and background tasks. Hold the lock while touching any String or
  // vector member outside the main loop. The DNS hot path never takes it; it
  // works from its own copies (see DnsServer53::applyConfig).
  static AppConfig cfg;
  static void lock();
  static void unlock();
  static bool begin();          // mount LittleFS + load config
  static bool load();
  static bool save();
  static void setAdminPassword(const String &plainPassword);
  static bool checkAdminPassword(const String &plainPassword);
  static String sha256Hex(const String &input);
};

struct CfgLock {
  CfgLock() { ConfigStore::lock(); }
  ~CfgLock() { ConfigStore::unlock(); }
};
