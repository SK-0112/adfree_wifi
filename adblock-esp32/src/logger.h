#pragma once
#include <Arduino.h>
#include <vector>

// RAM ring buffer for debug logs. Flushed to LittleFS in small batches
// on a timer to avoid excessive flash writes (never per-line).
class Logger {
public:
  static void begin();
  static void log(const String &line);
  static void loop(); // call periodically to flush batched lines to flash
  static std::vector<String> recent(size_t maxLines);

private:
  static std::vector<String> _ring;
  static size_t _maxRing;
  static std::vector<String> _pendingFlush;
  static uint32_t _lastFlushMs;
};
