#pragma once
#include <Arduino.h>

struct OtaStatus {
  bool inProgress = false;
  int percent = 0;
  String lastResult;
  String availableVersion;
  bool pendingVerify = false; // running a freshly-installed image, not yet marked good
};

class Ota {
public:
  static void begin();               // handles rollback bookkeeping on boot
  static void markCurrentImageGood(); // call once the system proves itself healthy
  static void checkAndUpdate();      // fetch manifest; update if a newer version exists
  static void requestCheck();        // spawn background task
  static OtaStatus status();
  static bool applyUploadedBegin(size_t size);
  static bool applyUploadedWrite(uint8_t *data, size_t len);
  static bool applyUploadedEnd();
private:
  static void task(void *param);
};
