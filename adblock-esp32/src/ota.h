#pragma once
#include <Arduino.h>

struct OtaStatus {
  bool inProgress = false;
  int percent = 0;
  String lastResult;
  String availableVersion;
  bool pendingVerify = false; // running a freshly-installed image, not yet marked good
  long lastCheckAgo = -1;     // seconds since the last manifest check, -1 never
};

class Ota {
public:
  static void begin();                // rollback bookkeeping on boot
  static void loop();                 // runs the daily automatic check when enabled
  static void markCurrentImageGood(); // call once the system proves itself healthy
  static void requestCheck();         // background check, installs if newer
  static OtaStatus status();
  static bool busy();

  // Manual upload from the dashboard. uploadBegin() returns false if a
  // manifest update is already running.
  static bool uploadBegin();
  static bool uploadWrite(uint8_t *data, size_t len);
  static bool uploadEnd();
  static void uploadAbort();

  // -1, 0, 1 comparing dotted versions numerically ("1.10.0" > "1.9.2").
  static int compareVersions(const String &a, const String &b);

private:
  static void task(void *param);
  static void checkAndUpdate();
};
