#pragma once
#include <Arduino.h>

struct BlocklistStatus {
  size_t domainCount = 0;
  time_t lastUpdateEpoch = 0;
  bool lastUpdateOk = false;
  String lastError;
  bool refreshInProgress = false;
  uint32_t sourcesOk = 0;
  uint32_t sourcesFailed = 0;
};

class Blocklist {
public:
  static void begin();                  // load compiled blocklist.bin from flash if present
  static void requestRefresh();         // kick off a background refresh task (non-blocking)
  static void loopMaintenance();        // call periodically; triggers scheduled refresh
  static bool isBlocked(const String &domainLower);
  static BlocklistStatus status();

  // whitelist / blacklist (user overrides), backed by ConfigStore + kept mirrored in RAM sets
  static void reloadOverrides(); // call after whitelist/blacklist config changes

private:
  static void refreshTask(void *param);
};
