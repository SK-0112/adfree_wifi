#pragma once
#include <Arduino.h>
#include <vector>

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
  std::vector<String> upstream_dns = {"1.1.1.1", "8.8.8.8", "1.0.0.1"};
  uint16_t dns_timeout_ms = 1200;

  // blocklist - these defaults match the tuned production set, so a freshly
  // flashed board comes up with the same coverage without any manual setup
  std::vector<String> blocklist_urls = {
      "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.plus.txt",
      "https://big.oisd.nl/",
      "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt"};
  uint32_t refresh_interval_hours = 24;
  std::vector<String> whitelist;
  std::vector<String> blacklist;

  // control
  bool enabled = true;
  uint32_t pause_until_epoch = 0; // 0 = not paused
  bool pause_indefinite = false;

  // ota
  String ota_manifest_url;
  String fw_version = "1.0.0";

  // led
  bool led_enabled = true;

  // internal / first-boot marker
  bool provisioned = false;
};

class ConfigStore {
public:
  static AppConfig cfg;
  static bool begin();          // mount LittleFS + load config
  static bool load();
  static bool save();
  static void setAdminPassword(const String &plainPassword);
  static bool checkAdminPassword(const String &plainPassword);
  static String sha256Hex(const String &input);
};
