#pragma once
#include <Arduino.h>
#include <vector>

struct DnsStats {
  uint32_t total = 0;
  uint32_t blocked = 0;
  uint32_t forwarded = 0;
  uint32_t upstreamTimeouts = 0;
  uint32_t upstreamErrors = 0;
  uint32_t droppedNonLocal = 0;
};

struct BlockedEntry {
  String domain;
  time_t when;
  String client;
};

class DnsServer53 {
public:
  static bool begin();
  static void loop();               // expire/retry pending queries, drain block log
  static DnsStats stats();
  static void resetStats();
  static std::vector<BlockedEntry> recentBlocked(size_t n);
  static bool upstreamHealthy();
  static bool blockingActive();     // false when disabled or paused
  static String activeUpstream();
};
