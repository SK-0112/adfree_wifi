#pragma once
#include <Arduino.h>
#include <vector>

struct SourceResult {
  String url;
  bool ok = false;
  uint32_t entries = 0;
  String err;
};

struct BlocklistStatus {
  size_t domainCount = 0;
  size_t capacity = 0;
  time_t lastUpdateEpoch = 0;
  bool lastUpdateOk = false;
  String lastError;
  bool refreshInProgress = false;
  uint32_t sourcesOk = 0;
  uint32_t sourcesFailed = 0;
  int32_t nextRefreshSecs = -1; // seconds until the next scheduled refresh, -1 unknown
  std::vector<SourceResult> sources;
};

enum class Verdict : uint8_t {
  NONE = 0,  // not on any list: forward
  LIST = 1,  // blocked by a downloaded blocklist
  DENY = 2,  // blocked by the user's denylist
  ALLOW = 3, // on the user's allowlist: forward even if a list has it
};

class Blocklist {
public:
  static void begin();                  // load the stored table from flash if present
  static void requestRefresh();         // start a background refresh (non-blocking)
  static void loopMaintenance();        // call from loop(); runs scheduled refreshes
  static BlocklistStatus status();

  // Lookup for the DNS hot path: no heap allocation, safe from any task.
  // `name` must already be lowercase. On a hit, *matchOff is the offset in
  // `name` of the suffix that matched (0 = the whole name).
  static Verdict check(const char *name, size_t len, size_t *matchOff = nullptr);
  static bool isBlocked(const char *name, size_t len) {
    Verdict v = check(name, len);
    return v == Verdict::LIST || v == Verdict::DENY;
  }

  // Rebuild the allow/deny tables from ConfigStore. Call after editing them.
  static void reloadOverrides();

private:
  static void refreshTask(void *param);
};
