#include "ota.h"
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <Update.h>
#include <Preferences.h>
#include <ArduinoJson.h>
#include <esp_ota_ops.h>
#include <esp_partition.h>
#include <esp_random.h>
#include <mbedtls/sha256.h>
#include <atomic>
#include "config.h"
#include "logger.h"
#include "led_status.h"
#include "version.h"
#include "ota_roots.h"

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
// Trust: the manifest and the image are fetched over HTTPS and the server
// certificate is verified against the roots in ota_roots.h. The SHA-256 in the
// manifest then guards the image against corruption in transit. Without the
// certificate check the hash would prove nothing: whoever can swap the image
// can swap the manifest too.
// ---------------------------------------------------------------------------

static SemaphoreHandle_t s_mux = nullptr;
static OtaStatus s_st;
static std::atomic<bool> s_busy(false);
static TaskHandle_t s_task = nullptr;
static Preferences s_prefs;
static bool s_markedGood = false;
static const int MAX_BOOT_TRIES = 3;
static uint32_t s_lastCheckMs = 0;
static bool s_checked = false;
static uint32_t s_firstCheckMs = 0;

static const uint32_t CHECK_EVERY_MS = 24UL * 3600UL * 1000UL;

static void setResult(const String &r) {
  xSemaphoreTake(s_mux, portMAX_DELAY);
  s_st.lastResult = r;
  xSemaphoreGive(s_mux);
  Logger::log("ota: " + r);
}

static void setProgress(bool inProgress, int pct) {
  xSemaphoreTake(s_mux, portMAX_DELAY);
  s_st.inProgress = inProgress;
  s_st.percent = pct;
  xSemaphoreGive(s_mux);
}

OtaStatus Ota::status() {
  xSemaphoreTake(s_mux, portMAX_DELAY);
  OtaStatus s = s_st;
  xSemaphoreGive(s_mux);
  s.lastCheckAgo = s_checked ? (long)((millis() - s_lastCheckMs) / 1000) : -1;
  return s;
}

bool Ota::busy() { return s_busy; }

int Ota::compareVersions(const String &a, const String &b) {
  const char *pa = a.c_str(), *pb = b.c_str();
  if (*pa == 'v') pa++;
  if (*pb == 'v') pb++;
  for (int i = 0; i < 4; i++) {
    char *ea, *eb;
    long x = strtol(pa, &ea, 10), y = strtol(pb, &eb, 10);
    if (x != y) return x < y ? -1 : 1;
    pa = ea;
    pb = eb;
    if (*pa == '.') pa++;
    if (*pb == '.') pb++;
    if (!*pa && !*pb) break;
  }
  return 0;
}

void Ota::begin() {
  if (!s_mux) s_mux = xSemaphoreCreateMutex();
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
        esp_ota_set_boot_partition(prev);
        delay(300);
        ESP.restart();
      }
    }
  }
  s_prefs.remove("pendver"); // 1.0.x bookkeeping; the version is compiled in now

  const esp_partition_t *run = esp_ota_get_running_partition();
  if (run) Logger::log(String("ota: firmware " ADFREE_FW_VERSION " running from '") + run->label + "'");
  // Spread automatic checks out so every board doesn't hit GitHub at once.
  s_firstCheckMs = 10UL * 60UL * 1000UL + (esp_random() % (50UL * 60UL * 1000UL));
}

void Ota::markCurrentImageGood() {
  if (s_markedGood) return;
  s_markedGood = true;
  if (s_prefs.getBool("pending", false)) {
    s_prefs.putBool("pending", false);
    s_prefs.putInt("tries", 0);
    Logger::log("ota: firmware " ADFREE_FW_VERSION " verified healthy, rollback disarmed");
  }
  xSemaphoreTake(s_mux, portMAX_DELAY);
  s_st.pendingVerify = false;
  xSemaphoreGive(s_mux);
  esp_ota_mark_app_valid_cancel_rollback();
}

static void armRollbackGuard() {
  s_prefs.putBool("pending", true);
  s_prefs.putInt("tries", 0);
}

// --------------------------- manifest OTA -----------------------------------

static bool httpOpen(HTTPClient &http, WiFiClientSecure &secure, const String &url) {
  if (!url.startsWith("https://")) return false; // see the trust note at the top
  http.setFollowRedirects(HTTPC_STRICT_FOLLOW_REDIRECTS);
  http.setTimeout(20000);
  http.setReuse(false);
  http.useHTTP10(true); // no chunked encoding: we read the raw stream
  secure.setCACert(OTA_ROOT_CAS);
  secure.setTimeout(20);
  return http.begin(secure, url);
}

void Ota::checkAndUpdate() {
  String manifestUrl;
  {
    CfgLock g;
    manifestUrl = ConfigStore::cfg.ota_manifest_url;
  }
  s_checked = true;
  s_lastCheckMs = millis();
  if (manifestUrl.isEmpty()) { setResult("no update URL configured"); return; }
  if (WiFi.status() != WL_CONNECTED) { setResult("Wi-Fi down"); return; }
  // Certificate validity can't be checked before NTP has set the clock.
  if (time(nullptr) < 1700000000) { setResult("clock not set yet, try again shortly"); return; }

  // ---- 1. fetch manifest ----
  String body;
  {
    HTTPClient http;
    WiFiClientSecure sec;
    if (!httpOpen(http, sec, manifestUrl)) { setResult("update URL must start with https://"); return; }
    int code = http.GET();
    if (code != HTTP_CODE_OK) {
      setResult(code < 0 ? "manifest: " + HTTPClient::errorToString(code) : "manifest HTTP " + String(code));
      http.end();
      return;
    }
    if (http.getSize() > 4096) { setResult("manifest too large"); http.end(); return; }
    body = http.getString();
    http.end();
  }

  JsonDocument doc;
  if (deserializeJson(doc, body)) { setResult("manifest is not valid JSON"); return; }
  String newVer = doc["version"] | "";
  String binUrl = doc["url"] | "";
  String wantSha = doc["sha256"] | "";
  wantSha.toLowerCase();
  xSemaphoreTake(s_mux, portMAX_DELAY);
  s_st.availableVersion = newVer;
  xSemaphoreGive(s_mux);

  if (newVer.isEmpty() || binUrl.isEmpty()) { setResult("manifest missing version or url"); return; }
  if (compareVersions(newVer, ADFREE_FW_VERSION) <= 0) {
    setResult("up to date (" ADFREE_FW_VERSION ")");
    return;
  }
  if (wantSha.length() != 64) { setResult("manifest has no sha256, refusing to install"); return; }

  Logger::log("ota: updating " ADFREE_FW_VERSION " -> " + newVer);
  LedStatus::setState(LedState::UPDATING);
  setProgress(true, 0);

  // ---- 2. stream the image into the inactive OTA slot ----
  HTTPClient http;
  WiFiClientSecure sec;
  if (!httpOpen(http, sec, binUrl)) {
    setResult("firmware URL must start with https://");
    setProgress(false, 0);
    return;
  }
  int code = http.GET();
  if (code != HTTP_CODE_OK) {
    setResult(code < 0 ? "firmware: " + HTTPClient::errorToString(code) : "firmware HTTP " + String(code));
    http.end();
    setProgress(false, 0);
    return;
  }
  int total = http.getSize();
  if (total <= 0) { setResult("firmware size unknown"); http.end(); setProgress(false, 0); return; }
  if (!Update.begin(total, U_FLASH)) {
    setResult("not enough room for the image: " + String(Update.errorString()));
    http.end();
    setProgress(false, 0);
    return;
  }

  mbedtls_sha256_context sha;
  mbedtls_sha256_init(&sha);
  mbedtls_sha256_starts(&sha, 0);
  WiFiClient *stream = http.getStreamPtr();
  uint8_t buf[1460];
  int written = 0;
  uint32_t lastData = millis();
  bool ioError = false;
  while (written < total) {
    size_t avail = stream->available();
    if (!avail) {
      if (millis() - lastData > 20000 || !stream->connected()) { ioError = true; break; }
      vTaskDelay(pdMS_TO_TICKS(2));
      continue;
    }
    lastData = millis();
    size_t want = std::min(std::min(avail, sizeof(buf)), (size_t)(total - written));
    int got = stream->readBytes(buf, want);
    if (got <= 0) continue;
    if (Update.write(buf, got) != (size_t)got) { ioError = true; break; }
    mbedtls_sha256_update(&sha, buf, got);
    written += got;
    setProgress(true, (int)((written * 100LL) / total));
  }
  unsigned char digest[32];
  mbedtls_sha256_finish(&sha, digest);
  mbedtls_sha256_free(&sha);
  char gotSha[65];
  for (int i = 0; i < 32; i++) sprintf(gotSha + i * 2, "%02x", digest[i]);
  gotSha[64] = 0;
  http.end();

  if (ioError || written != total) {
    Update.abort();
    setResult("download incomplete (" + String(written) + "/" + String(total) + " bytes)");
    setProgress(false, 0);
    return;
  }
  if (wantSha != String(gotSha)) {
    Update.abort();
    setResult("SHA-256 mismatch, image rejected");
    setProgress(false, 0);
    return;
  }
  if (!Update.end(true)) {
    setResult("install failed: " + String(Update.errorString()));
    setProgress(false, 0);
    return;
  }

  // ---- 3. arm rollback and reboot into the new image ----
  armRollbackGuard();
  setResult("installed " + newVer + ", rebooting");
  setProgress(false, 100);
  delay(800);
  ESP.restart();
}

void Ota::task(void *param) {
  Ota::checkAndUpdate();
  s_task = nullptr;
  s_busy = false;
  vTaskDelete(nullptr);
}

void Ota::requestCheck() {
  bool expected = false;
  if (!s_busy.compare_exchange_strong(expected, true)) return;
  if (xTaskCreatePinnedToCore(Ota::task, "ota", 12288, nullptr, 1, &s_task, 0) != pdPASS) {
    s_busy = false;
    setResult("could not start update task (low memory)");
  }
}

void Ota::loop() {
  if (!ConfigStore::cfg.ota_auto || s_busy || WiFi.status() != WL_CONNECTED) return;
  uint32_t ms = millis();
  if (!s_checked) {
    if (ms < s_firstCheckMs) return;
  } else if (ms - s_lastCheckMs < CHECK_EVERY_MS) {
    return;
  }
  s_checked = true;
  s_lastCheckMs = ms; // also rate-limits retries if the check can't start
  Logger::log("ota: automatic update check");
  requestCheck();
}

// --------------------------- manual upload OTA ------------------------------

bool Ota::uploadBegin() {
  bool expected = false;
  if (!s_busy.compare_exchange_strong(expected, true)) {
    if (!Update.isRunning() || s_task) return false; // a manifest update owns it
    Update.abort();                                  // stale upload from a closed tab
  }
  setProgress(true, 0);
  LedStatus::setState(LedState::UPDATING);
  if (!Update.begin(UPDATE_SIZE_UNKNOWN, U_FLASH)) {
    setResult("upload: " + String(Update.errorString()));
    setProgress(false, 0);
    s_busy = false;
    return false;
  }
  Logger::log("ota: manual upload started");
  return true;
}

bool Ota::uploadWrite(uint8_t *data, size_t len) {
  if (!Update.isRunning()) return false;
  if (Update.write(data, len) != len) {
    setResult("upload write failed: " + String(Update.errorString()));
    Update.abort();
    setProgress(false, 0);
    s_busy = false;
    return false;
  }
  return true;
}

bool Ota::uploadEnd() {
  bool ok = Update.isRunning() && Update.end(true);
  setProgress(false, ok ? 100 : 0);
  if (ok) {
    armRollbackGuard();
    setResult("manual upload installed, rebooting");
  } else {
    setResult("manual upload failed: " + String(Update.errorString()));
    s_busy = false;
  }
  return ok;
}

void Ota::uploadAbort() {
  if (Update.isRunning()) Update.abort();
  setProgress(false, 0);
  s_busy = false;
}
