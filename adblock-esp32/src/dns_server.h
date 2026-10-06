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

// One line of the query log. `verdict` is a Verdict value from blocklist.h.
struct QueryEntry {
  char domain[96];
  uint32_t client;   // IPv4, network order as IPAddress stores it
  uint32_t uptime;   // seconds since boot when it happened
  uint16_t qtype;
  uint8_t verdict;
};

struct TopDomain {
  String domain;
  uint32_t count;
};

struct ClientStat {
  uint32_t ip;
  uint32_t queries;
  uint32_t blocked;
  uint32_t lastSeen; // uptime seconds
};

static const size_t HISTORY_BUCKETS = 144;     // 24 h ...
static const uint32_t HISTORY_STEP_S = 600;    // ... in 10-minute buckets

struct History {
  uint32_t q[HISTORY_BUCKETS];
  uint32_t b[HISTORY_BUCKETS];
  uint32_t ageInBucket; // seconds already elapsed in the newest bucket
};

class DnsServer53 {
public:
  static bool begin();
  static void loop();               // expire/retry pending queries, drain the query log
  static void applyConfig();        // re-read upstreams after a settings change
  static DnsStats stats();
  static void resetStats();
  static bool upstreamHealthy();
  static bool blockingActive();     // false when disabled or paused
  static String activeUpstream();
  static uint32_t uptimeSec();

  static std::vector<QueryEntry> recentQueries(size_t n); // newest first
  static std::vector<TopDomain> topBlocked(size_t n);
  static std::vector<ClientStat> topClients(size_t n);
  static size_t activeClients(uint32_t withinSec);
  static History history();
};
