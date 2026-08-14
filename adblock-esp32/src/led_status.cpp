#include "led_status.h"
#include <Adafruit_NeoPixel.h>
#include "config.h"

#ifndef ADBLOCK_LED_PIN
#define ADBLOCK_LED_PIN 48
#endif

static Adafruit_NeoPixel pixel(1, ADBLOCK_LED_PIN, NEO_GRB + NEO_KHZ800);

LedState LedStatus::_state = LedState::BOOTING;
uint32_t LedStatus::_lastUpdate = 0;
uint8_t LedStatus::_phase = 0;

// Kept deliberately dim so the LED is informative but not distracting.
static const uint8_t MAXB = 40;

void LedStatus::begin() {
  pixel.begin();
  pixel.setBrightness(MAXB);
  pixel.clear();
  pixel.show();
}

void LedStatus::setState(LedState s) { _state = s; }

static void showColor(uint8_t r, uint8_t g, uint8_t b) {
  pixel.setPixelColor(0, pixel.Color(r, g, b));
  pixel.show();
}

void LedStatus::loop() {
  if (!ConfigStore::cfg.led_enabled) {
    showColor(0, 0, 0);
    return;
  }
  uint32_t now = millis();
  if (now - _lastUpdate < 40) return; // ~25fps update budget, cheap
  _lastUpdate = now;
  _phase++;

  switch (_state) {
    case LedState::BOOTING: {
      // slow blue pulse
      uint8_t v = (uint8_t)((sinf(_phase * 0.05f) * 0.5f + 0.5f) * 255);
      showColor(0, 0, v);
      break;
    }
    case LedState::HEALTHY: {
      // brief dim green heartbeat every ~4s, off otherwise (unobtrusive)
      uint16_t cycle = _phase % 100;
      uint8_t v = (cycle < 6) ? 200 : 0;
      showColor(0, v, 0);
      break;
    }
    case LedState::DEGRADED: {
      uint8_t v = (uint8_t)((sinf(_phase * 0.08f) * 0.5f + 0.5f) * 255);
      showColor(v, v / 2, 0); // amber
      break;
    }
    case LedState::UPDATING: {
      uint8_t v = ((_phase / 3) % 2) ? 255 : 0;
      showColor(0, 0, v);
      break;
    }
    case LedState::ERROR: {
      uint8_t v = ((_phase / 5) % 2) ? 255 : 0;
      showColor(v, 0, 0);
      break;
    }
    case LedState::PAUSED: {
      showColor(60, 0, 60);
      break;
    }
    case LedState::AP_PORTAL: {
      uint8_t v = (uint8_t)((sinf(_phase * 0.05f) * 0.5f + 0.5f) * 180);
      showColor(v, v, v);
      break;
    }
  }
}
