#pragma once
#include <Arduino.h>

enum class LedState {
  BOOTING,     // slow blue pulse
  HEALTHY,     // dim green heartbeat blink
  DEGRADED,    // amber pulse (blocklist stale / upstream unhealthy / fail-open)
  UPDATING,    // fast blue blink
  ERROR,       // red blink
  PAUSED,      // dim purple solid
  AP_PORTAL    // slow white pulse (wifi setup portal active)
};

class LedStatus {
public:
  static void begin();
  static void setState(LedState s);
  static void loop(); // call frequently from main loop
private:
  static LedState _state;
  static uint32_t _lastUpdate;
  static uint8_t _phase;
};
