#include "logger.h"
#include <LittleFS.h>
#include "blocklist.h"

std::vector<String> Logger::_ring;
size_t Logger::_maxRing = 150;
std::vector<String> Logger::_pendingFlush;
uint32_t Logger::_lastFlushMs = 0;

static const char *LOG_PATH = "/log.txt";
static const size_t LOG_MAX_BYTES = 150 * 1024;

void Logger::begin() {
  _ring.reserve(_maxRing);
  _lastFlushMs = millis();
}

void Logger::log(const String &line) {
  char ts[16];
  snprintf(ts, sizeof(ts), "[%10lu] ", (unsigned long)(millis() / 1000));
  String full = String(ts) + line;
  Serial.println(full);
  _ring.push_back(full);
  if (_ring.size() > _maxRing) _ring.erase(_ring.begin());
  _pendingFlush.push_back(full);
}

std::vector<String> Logger::recent(size_t maxLines) {
  if (_ring.size() <= maxLines) return _ring;
  return std::vector<String>(_ring.end() - maxLines, _ring.end());
}

void Logger::loop() {
  uint32_t now = millis();
  // Flush every 5 minutes, or immediately if a lot has queued up.
  bool timeToFlush = (now - _lastFlushMs > 5UL * 60UL * 1000UL);
  bool bufferFull = _pendingFlush.size() >= 40;
  if (_pendingFlush.empty() || !(timeToFlush || bufferFull)) return;

  // Never contend with a blocklist refresh for the filesystem lock - a big
  // list write can hold it for a long time and we'd block the main loop.
  if (Blocklist::status().refreshInProgress) return;
  if (_pendingFlush.size() > 400) {
    _pendingFlush.erase(_pendingFlush.begin(), _pendingFlush.end() - 200);
  }

  File f = LittleFS.open(LOG_PATH, "a");
  if (!f) {
    // If append fails (e.g. file doesn't exist yet), try create.
    f = LittleFS.open(LOG_PATH, "w");
  }
  if (f) {
    if (f.size() > LOG_MAX_BYTES) {
      f.close();
      LittleFS.remove(LOG_PATH);
      f = LittleFS.open(LOG_PATH, "w");
    }
    for (auto &l : _pendingFlush) {
      f.println(l);
    }
    f.close();
  }
  _pendingFlush.clear();
  _lastFlushMs = now;
}
