#include "config.h"
#include <LittleFS.h>
#include <ArduinoJson.h>
#include <mbedtls/sha256.h>
#include "logger.h"

AppConfig ConfigStore::cfg;
static const char *CFG_PATH = "/config.json";

static void arrToJson(JsonArray arr, const std::vector<String> &v) {
  for (auto &s : v) arr.add(s);
}
static void jsonToArr(JsonArrayConst arr, std::vector<String> &v) {
  v.clear();
  for (JsonVariantConst x : arr) v.push_back(x.as<String>());
}

String ConfigStore::sha256Hex(const String &input) {
  unsigned char hash[32];
  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);
  mbedtls_sha256_starts(&ctx, 0);
  mbedtls_sha256_update(&ctx, (const unsigned char *)input.c_str(), input.length());
  mbedtls_sha256_finish(&ctx, hash);
  mbedtls_sha256_free(&ctx);
  char hex[65];
  for (int i = 0; i < 32; i++) sprintf(hex + i * 2, "%02x", hash[i]);
  hex[64] = 0;
  return String(hex);
}

void ConfigStore::setAdminPassword(const String &plainPassword) {
  cfg.admin_pass_hash = sha256Hex(plainPassword);
}

bool ConfigStore::checkAdminPassword(const String &plainPassword) {
  return sha256Hex(plainPassword) == cfg.admin_pass_hash;
}

bool ConfigStore::begin() {
  if (!LittleFS.begin(true)) {
    Serial.println("[cfg] LittleFS mount failed even after format!");
    return false;
  }
  return load();
}

bool ConfigStore::load() {
  if (!LittleFS.exists(CFG_PATH)) {
    Serial.println("[cfg] no config.json, using defaults");
    return false;
  }
  File f = LittleFS.open(CFG_PATH, "r");
  if (!f) return false;
  JsonDocument doc;
  DeserializationError err = deserializeJson(doc, f);
  f.close();
  if (err) {
    Serial.printf("[cfg] parse error: %s\n", err.c_str());
    return false;
  }

  cfg.wifi_ssid = doc["wifi_ssid"] | cfg.wifi_ssid;
  cfg.wifi_pass = doc["wifi_pass"] | cfg.wifi_pass;
  cfg.use_static_ip = doc["use_static_ip"] | cfg.use_static_ip;
  cfg.static_ip = doc["static_ip"] | cfg.static_ip;
  cfg.static_gw = doc["static_gw"] | cfg.static_gw;
  cfg.static_subnet = doc["static_subnet"] | cfg.static_subnet;
  cfg.hostname = doc["hostname"] | cfg.hostname;
  cfg.admin_user = doc["admin_user"] | cfg.admin_user;
  cfg.admin_pass_hash = doc["admin_pass_hash"] | cfg.admin_pass_hash;
  cfg.ap_pass = doc["ap_pass"] | cfg.ap_pass;
  cfg.dns_timeout_ms = doc["dns_timeout_ms"] | cfg.dns_timeout_ms;
  cfg.refresh_interval_hours = doc["refresh_interval_hours"] | cfg.refresh_interval_hours;
  cfg.enabled = doc["enabled"] | cfg.enabled;
  cfg.pause_until_epoch = doc["pause_until_epoch"] | cfg.pause_until_epoch;
  cfg.pause_indefinite = doc["pause_indefinite"] | cfg.pause_indefinite;
  cfg.ota_manifest_url = doc["ota_manifest_url"] | cfg.ota_manifest_url;
  cfg.fw_version = doc["fw_version"] | cfg.fw_version;
  cfg.led_enabled = doc["led_enabled"] | cfg.led_enabled;
  cfg.provisioned = doc["provisioned"] | cfg.provisioned;

  if (doc["upstream_dns"].is<JsonArray>()) jsonToArr(doc["upstream_dns"], cfg.upstream_dns);
  if (doc["blocklist_urls"].is<JsonArray>()) jsonToArr(doc["blocklist_urls"], cfg.blocklist_urls);
  if (doc["whitelist"].is<JsonArray>()) jsonToArr(doc["whitelist"], cfg.whitelist);
  if (doc["blacklist"].is<JsonArray>()) jsonToArr(doc["blacklist"], cfg.blacklist);

  Serial.println("[cfg] loaded config.json");
  return true;
}

bool ConfigStore::save() {
  JsonDocument doc;
  doc["wifi_ssid"] = cfg.wifi_ssid;
  doc["wifi_pass"] = cfg.wifi_pass;
  doc["use_static_ip"] = cfg.use_static_ip;
  doc["static_ip"] = cfg.static_ip;
  doc["static_gw"] = cfg.static_gw;
  doc["static_subnet"] = cfg.static_subnet;
  doc["hostname"] = cfg.hostname;
  doc["admin_user"] = cfg.admin_user;
  doc["admin_pass_hash"] = cfg.admin_pass_hash;
  doc["ap_pass"] = cfg.ap_pass;
  doc["dns_timeout_ms"] = cfg.dns_timeout_ms;
  doc["refresh_interval_hours"] = cfg.refresh_interval_hours;
  doc["enabled"] = cfg.enabled;
  doc["pause_until_epoch"] = cfg.pause_until_epoch;
  doc["pause_indefinite"] = cfg.pause_indefinite;
  doc["ota_manifest_url"] = cfg.ota_manifest_url;
  doc["fw_version"] = cfg.fw_version;
  doc["led_enabled"] = cfg.led_enabled;
  doc["provisioned"] = cfg.provisioned;

  arrToJson(doc["upstream_dns"].to<JsonArray>(), cfg.upstream_dns);
  arrToJson(doc["blocklist_urls"].to<JsonArray>(), cfg.blocklist_urls);
  arrToJson(doc["whitelist"].to<JsonArray>(), cfg.whitelist);
  arrToJson(doc["blacklist"].to<JsonArray>(), cfg.blacklist);

  // write to temp file then rename, so a power loss mid-write can't corrupt config
  const char *tmpPath = "/config.json.tmp";
  File f = LittleFS.open(tmpPath, "w");
  if (!f) {
    Logger::log("cfg: failed to open temp config for write");
    return false;
  }
  serializeJson(doc, f);
  f.close();

  LittleFS.remove(CFG_PATH);
  if (!LittleFS.rename(tmpPath, CFG_PATH)) {
    Logger::log("cfg: rename failed");
    return false;
  }
  Logger::log("cfg: config.json saved");
  return true;
}
