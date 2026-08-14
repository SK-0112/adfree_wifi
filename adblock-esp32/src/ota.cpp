#include "ota.h"
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <Update.h>
#include <Preferences.h>
#include <ArduinoJson.h>
#include <esp_ota_ops.h>
#include <esp_partition.h>
#include <mbedtls/sha256.h>
#include "config.h"
#include "logger.h"
#include "led_status.h"

// ---------------------------------------------------------------------------
// OTA with a software rollback net.
//
// Arduino's prebuilt bootloader does not reliably enable IDF's automatic
// rollback, so we implement our own: before switching the boot partition we
// set a "pending" flag in NVS. Every boot while that flag is set increments a
// try counter. The app clears the flag only after it has proven itself healthy
// (Wi-Fi up + DNS listening for 60s). If a bad image crash-loops, the counter
// reaches its limit and we set the boot partition back to the previous app.
//
// Firmware integrity is enforced by SHA-256 from the manifest - the image is
// hashed as it streams in and is never made bootable if the digest mismatches.
// ---------------------------------------------------------------------------

static OtaStatus s_st;
static TaskHandle_t s_task = nullptr;
static Preferences s_prefs;
static bool s_markedGood = false;
static const int MAX_BOOT_TRIES = 3;

OtaStatus Ota::status() { return s_st; }

void Ota::begin() {
  s_prefs.begin("otaguard", false);
  bool pending = s_prefs.getBool("pending", false);
  s_st.pendingVerify = pending;

  if (pending) {
    int tries = s_prefs.getInt("tries", 0) + 1;
    s_prefs.putInt("tries", tries);
    Logger::log("ota: running unverified image, boot attempt " + String(tries));

    if (tries > MAX_BOOT_TRIES) {
      const esp_partition_t *prev = esp_ota_get_next_update_partition(NULL);
      if (prev) {
        Logger::log("ota: too many failed boots - ROLLING BACK to previous firmware");
        s_prefs.putBool("pending", false);
        s_prefs.putInt("tries", 0);
        s_prefs.remove("pendver"); // the candidate version never became real
        esp_ota_set_boot_partition(prev);
        delay(300);
        ESP.restart();
      }
    }
  }

  const esp_partition_t *run = esp_ota_get_running_partition();
  if (run) Logger::log("ota: running from partition '" + String(run->label) + "'");
}

void Ota::markCurrentImageGood() {
  if (s_markedGood) return;
  s_markedGood = true;
  if (s_prefs.getBool("pending", false)) {
    s_prefs.putBool("pending", false);
    s_prefs.putInt("tries", 0);
    // Only now does the candidate version become the recorded version. If we
    // had rolled back instead, the old version string would still be correct.
    String pv = s_prefs.getString("pendver", "");
    if (pv.length()) {
      ConfigStore::cfg.fw_version = pv;
      ConfigStore::save();
      s_prefs.remove("pendver");
    }
    Logger::log("ota: firmware " + ConfigStore::cfg.fw_version +
                " verified healthy, rollback disarmed");
  }
  s_st.pendingVerify = false;
  esp_ota_mark_app_valid_cancel_rollback();
}

static void armRollbackGuard() {
  s_prefs.putBool("pending", true);
  s_prefs.putInt("tries", 0);
}

// --------------------------- manifest OTA -----------------------------------

static bool httpOpen(HTTPClient &http, WiFiClientSecure *&secure, const String &url) {
  http.setFollowRedirects(HTTPC_STRICT_FOLLOW_REDIRECTS);
  http.setTimeout(20000);
  http.setReuse(false);
  if (url.startsWith("https://")) {
    secure = new WiFiClientSecure();
    secure->setInsecure(); // integrity comes from the SHA-256 check below
    secure->setTimeout(20);
    return http.begin(*secure, url);
  }
  secure = nullptr;
  return http.begin(url);
}

void Ota::checkAndUpdate() {
  if (ConfigStore::cfg.ota_manifest_url.isEmpty()) {
    s_st.lastResult = "no manifest URL configured";
    return;
  }
  if (WiFi.status() != WL_CONNECTED) {
    s_st.lastResult = "wifi down";
    return;
  }

  // ---- 1. fetch manifest ----
  HTTPClient http;
  WiFiClientSecure *sec = nullptr;
  if (!httpOpen(http, sec, ConfigStore::cfg.ota_manifest_url)) {
    s_st.lastResult = "manifest begin failed";
    if (sec) delete sec;
    return;
  }
  int code = http.GET();
  if (code != HTTP_CODE_OK) {
    s_st.lastResult = "manifest HTTP " + String(code);
    http.end();
    if (sec) delete sec;
    Logger::log("ota: " + s_st.lastResult);
    return;
  }
  String body = http.getString();
  http.end();
  if (sec) { delete sec; sec = nullptr; }

  JsonDocument doc;
  if (deserializeJson(doc, body)) {
    s_st.lastResult = "manifest parse error";
    Logger::log("ota: " + s_st.lastResult);
    return;
  }
  String newVer = doc["version"] | "";
  String binUrl = doc["url"] | "";
  String wantSha = doc["sha256"] | "";
  wantSha.toLowerCase();

  s_st.availableVersion = newVer;
  if (newVer.isEmpty() || binUrl.isEmpty()) {
    s_st.lastResult = "manifest missing version/url";
    return;
  }
  if (newVer == ConfigStore::cfg.fw_version) {
    s_st.lastResult = "already up to date (" + newVer + ")";
    Logger::log("ota: " + s_st.lastResult);
    return;
  }
  if (wantSha.length() != 64) {
    s_st.lastResult = "manifest missing sha256 - refusing to install";
    Logger::log("ota: " + s_st.lastResult);
    return;
  }

  Logger::log("ota: updating " + ConfigStore::cfg.fw_version + " -> " + newVer);
  LedStatus::setState(LedState::UPDATING);
  s_st.inProgress = true;
  s_st.percent = 0;

  // ---- 2. stream the image into the inactive OTA slot ----
  if (!httpOpen(http, sec, binUrl)) {
    s_st.lastResult = "firmware begin failed";
    s_st.inProgress = false;
    if (sec) delete sec;
    return;
  }
  code = http.GET();
  if (code != HTTP_CODE_OK) {
    s_st.lastResult = "firmware HTTP " + String(code);
    http.end();
    if (sec) delete sec;
    s_st.inProgress = false;
    return;
  }
  int total = http.getSize();
  if (total <= 0) {
    s_st.lastResult = "firmware size unknown";
    http.end();
    if (sec) delete sec;
    s_st.inProgress = false;
    return;
  }

  if (!Update.begin(total, U_FLASH)) {
    s_st.lastResult = "Update.begin failed: " + String(Update.errorString());
    http.end();
    if (sec) delete sec;
    s_st.inProgress = false;
    return;
  }

  mbedtls_sha256_context sha;
  mbedtls_sha256_init(&sha);
  mbedtls_sha256_starts(&sha, 0);

  WiFiClient *stream = http.getStreamPtr();
  uint8_t buf[1024];
  int written = 0;
  uint32_t lastData = millis();
  bool ioError = false;

  while (written < total) {
    size_t avail = stream->available();
    if (!avail) {
      if (millis() - lastData > 20000) { ioError = true; break; }
      delay(2);
      if (!http.connected()) break;
      continue;
    }
    lastData = millis();
    int got = stream->readBytes(buf, avail > sizeof(buf) ? sizeof(buf) : avail);
    if (got <= 0) continue;
    if (Update.write(buf, got) != (size_t)got) { ioError = true; break; }
    mbedtls_sha256_update(&sha, buf, got);
    written += got;
    s_st.percent = (int)((written * 100L) / total);
  }

  unsigned char digest[32];
  mbedtls_sha256_finish(&sha, digest);
  mbedtls_sha256_free(&sha);
  char gotSha[65];
  for (int i = 0; i < 32; i++) sprintf(gotSha + i * 2, "%02x", digest[i]);
  gotSha[64] = 0;

  http.end();
  if (sec) delete sec;

  if (ioError || written != total) {
    Update.abort();
    s_st.lastResult = "download incomplete (" + String(written) + "/" + String(total) + ")";
    s_st.inProgress = false;
    Logger::log("ota: " + s_st.lastResult);
    LedStatus::setState(LedState::DEGRADED);
    return;
  }
  if (wantSha != String(gotSha)) {
    Update.abort();
    s_st.lastResult = "SHA-256 MISMATCH - image rejected";
    s_st.inProgress = false;
    Logger::log("ota: " + s_st.lastResult);
    LedStatus::setState(LedState::ERROR);
    return;
  }
  if (!Update.end(true)) {
    s_st.lastResult = "Update.end failed: " + String(Update.errorString());
    s_st.inProgress = false;
    Logger::log("ota: " + s_st.lastResult);
    return;
  }

  // ---- 3. arm rollback, stage the version, reboot into the new image ----
  // The version is only *staged* here; it is committed to config once the new
  // image has proven healthy, so a rollback leaves the version string honest.
  s_prefs.putString("pendver", newVer);
  armRollbackGuard();
  s_st.lastResult = "installed " + newVer + ", rebooting";
  s_st.inProgress = false;
  Logger::log("ota: " + s_st.lastResult);
  delay(800);
  ESP.restart();
}

void Ota::task(void *param) {
  Ota::checkAndUpdate();
  s_task = nullptr;
  vTaskDelete(nullptr);
}

void Ota::requestCheck() {
  if (s_task) return;
  xTaskCreatePinnedToCore(Ota::task, "ota", 12288, nullptr, 1, &s_task, 0);
}

// --------------------------- manual upload OTA ------------------------------

bool Ota::applyUploadedBegin(size_t size) {
  s_st.inProgress = true;
  s_st.percent = 0;
  LedStatus::setState(LedState::UPDATING);
  if (!Update.begin(size == 0 ? UPDATE_SIZE_UNKNOWN : size, U_FLASH)) {
    s_st.lastResult = "begin failed: " + String(Update.errorString());
    s_st.inProgress = false;
    return false;
  }
  Logger::log("ota: manual upload started");
  return true;
}

bool Ota::applyUploadedWrite(uint8_t *data, size_t len) {
  return Update.write(data, len) == len;
}

bool Ota::applyUploadedEnd() {
  bool ok = Update.end(true);
  s_st.inProgress = false;
  if (ok) {
    armRollbackGuard();
    s_st.lastResult = "manual upload OK, rebooting";
    Logger::log("ota: " + s_st.lastResult);
  } else {
    s_st.lastResult = "manual upload failed: " + String(Update.errorString());
    Logger::log("ota: " + s_st.lastResult);
  }
  return ok;
}
