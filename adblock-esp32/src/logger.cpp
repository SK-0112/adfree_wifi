#include "logger.h"
#include <LittleFS.h>
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>
#include "blocklist.h"

std::vector<String> Logger::_ring;
size_t Logger::_maxRing = 150;
std::vector<String> Logger::_pendingFlush;
uint32_t Logger::_lastFlushMs = 0;

// log() is called from the main loop, the AsyncTCP task (web handlers) and the
// blocklist/OTA tasks. std::vector is not thread-safe, so every touch of the
// buffers goes through this mutex.
static SemaphoreHandle_t s_mux = nullptr;

static const char *LOG_PATH = "/log.txt";
static const size_t LOG_MAX_BYTES = 150 * 1024;

void Logger::begin() {
  if (!s_mux) s_mux = xSemaphoreCreateMutex();
  _ring.reserve(_maxRing);
  _lastFlushMs = millis();
}

void Logger::log(const String &line) {
  uint32_t s = millis() / 1000;
  char ts[24];
  snprintf(ts, sizeof(ts), "[%lud %02lu:%02lu:%02lu] ", (unsigned long)(s / 86400),
           (unsigned long)(s / 3600 % 24), (unsigned long)(s / 60 % 60), (unsigned long)(s % 60));
  String full = String(ts) + line;
  Serial.println(full);
  if (!s_mux) s_mux = xSemaphoreCreateMutex();
  xSemaphoreTake(s_mux, portMAX_DELAY);
  if (_ring.size() >= _maxRing) _ring.erase(_ring.begin());
  _ring.push_back(full);
  if (_pendingFlush.size() < 400) _pendingFlush.push_back(full);
  xSemaphoreGive(s_mux);
}

std::vector<String> Logger::recent(size_t maxLines) {
  std::vector<String> out;
  if (!s_mux) return out;
  xSemaphoreTake(s_mux, portMAX_DELAY);
  size_t start = _ring.size() > maxLines ? _ring.size() - maxLines : 0;
  out.assign(_ring.begin() + start, _ring.end());
  xSemaphoreGive(s_mux);
  return out;
}

void Logger::loop() {
  uint32_t now = millis();
  if (!s_mux) return;
  // Flush every 5 minutes, or sooner if a lot has queued up.
  xSemaphoreTake(s_mux, portMAX_DELAY);
  bool due = !_pendingFlush.empty() &&
             (now - _lastFlushMs > 5UL * 60UL * 1000UL || _pendingFlush.size() >= 40);
  xSemaphoreGive(s_mux);
  if (!due) return;

  // Never contend with a blocklist refresh for the filesystem lock - a big
  // list write can hold it for a long time and we'd block the main loop.
  if (Blocklist::status().refreshInProgress) return;

  std::vector<String> batch;
  xSemaphoreTake(s_mux, portMAX_DELAY);
  batch.swap(_pendingFlush);
  xSemaphoreGive(s_mux);

  File f = LittleFS.open(LOG_PATH, "a");
  if (f && f.size() > LOG_MAX_BYTES) {
    // Keep one generation so a crash report isn't lost the moment we rotate.
    f.close();
    LittleFS.remove("/log.old.txt");
    LittleFS.rename(LOG_PATH, "/log.old.txt");
    f = LittleFS.open(LOG_PATH, "w");
  }
  if (f) {
    for (auto &l : batch) f.println(l);
    f.close();
  }
  _lastFlushMs = now;
}
