#include "dns_server.h"
#include <WiFi.h>
#include <AsyncUDP.h>
#include <freertos/queue.h>
#include "config.h"
#include "blocklist.h"
#include "logger.h"

// ---------------------------------------------------------------------------
// UDP/53 resolver.
//
// Design notes:
//  * Queries are answered from the lwIP async callback - all work on that path
//    is allocation-free and O(log n) at worst.
//  * Allowed queries are relayed to upstream with a rewritten transaction ID;
//    a small pending table maps replies back to the original client.
//  * Anything that goes wrong (no blocklist, paused, disabled, parse failure)
//    results in the query being FORWARDED, never dropped. The failure mode of
//    this device is "acts like a plain DNS relay", not "internet is down".
// ---------------------------------------------------------------------------

static const uint16_t DNS_PORT = 53;
static const uint16_t UPSTREAM_LOCAL_PORT = 5333;
static const size_t MAX_PENDING = 64;
static const size_t MAX_QUERY_COPY = 320;

struct Pending {
  bool used = false;
  uint16_t origId;
  uint16_t ourId;
  IPAddress clientIp;
  uint16_t clientPort;
  uint32_t sentMs;
  uint8_t upstreamIdx;
  bool retried;
  uint16_t qlen;
  uint8_t query[MAX_QUERY_COPY];
};

static AsyncUDP s_srv;
static AsyncUDP s_up;
static Pending s_pending[MAX_PENDING];
static portMUX_TYPE s_pendMux = portMUX_INITIALIZER_UNLOCKED;
static uint16_t s_nextId = 1;

static DnsStats s_stats;
static uint8_t s_upstreamIdx = 0;
static uint8_t s_consecFail = 0;
static bool s_upHealthy = true;

// blocked-domain notifications are handed to the main loop through a queue so
// that no allocation happens inside the lwIP callback
struct BlockMsg { char domain[96]; uint32_t clientIp; };
static QueueHandle_t s_blockQ = nullptr;
static std::vector<BlockedEntry> s_recentBlocked;
static const size_t RECENT_MAX = 40;

// --------------------------- helpers ---------------------------------------

static IPAddress currentUpstream() {
  auto &v = ConfigStore::cfg.upstream_dns;
  if (v.empty()) return IPAddress(1, 1, 1, 1);
  IPAddress ip;
  if (!ip.fromString(v[s_upstreamIdx % v.size()])) return IPAddress(1, 1, 1, 1);
  return ip;
}

static void rotateUpstream() {
  auto &v = ConfigStore::cfg.upstream_dns;
  if (v.size() > 1) {
    s_upstreamIdx = (s_upstreamIdx + 1) % v.size();
    Logger::log("dns: switching upstream to " + v[s_upstreamIdx]);
  }
}

bool DnsServer53::upstreamHealthy() { return s_upHealthy; }
String DnsServer53::activeUpstream() {
  auto &v = ConfigStore::cfg.upstream_dns;
  if (v.empty()) return "(none)";
  return v[s_upstreamIdx % v.size()];
}

bool DnsServer53::blockingActive() {
  if (!ConfigStore::cfg.enabled) return false;
  if (ConfigStore::cfg.pause_indefinite) return false;
  if (ConfigStore::cfg.pause_until_epoch) {
    time_t now = time(nullptr);
    // if the clock isn't set yet, treat a pending pause as active (safer:
    // user asked for ads through, we honour it until NTP confirms otherwise)
    if (now < 1700000000) return false;
    if ((uint32_t)now < ConfigStore::cfg.pause_until_epoch) return false;
  }
  return true;
}

// Only answer clients on our own LAN, so that if this device is ever exposed
// it can't be abused as an open resolver / DNS amplifier.
static bool isLocalClient(const IPAddress &ip) {
  IPAddress me = WiFi.localIP();
  IPAddress mask = WiFi.subnetMask();
  for (int i = 0; i < 4; i++) {
    if ((ip[i] & mask[i]) != (me[i] & mask[i])) return false;
  }
  return true;
}

// Extract the QNAME at offset 12 as a lowercase dotted string.
static bool parseQuestion(const uint8_t *b, size_t len, String &name,
                          uint16_t &qtype, size_t &qEnd) {
  if (len < 13) return false;
  size_t off = 12;
  name = "";
  int guard = 0;
  while (off < len && guard++ < 64) {
    uint8_t l = b[off];
    if (l == 0) { off++; break; }
    if ((l & 0xC0) == 0xC0) return false; // compression in a question: reject
    off++;
    if (off + l > len || l > 63) return false;
    if (name.length()) name += '.';
    for (uint8_t i = 0; i < l; i++) {
      char c = (char)b[off + i];
      if (c >= 'A' && c <= 'Z') c += 32;
      name += c;
    }
    off += l;
  }
  if (off + 4 > len) return false;
  qtype = (b[off] << 8) | b[off + 1];
  qEnd = off + 4;
  if (name.length() == 0 || name.length() > 253) return false;
  return true;
}

// Build a "blocked" reply in place: NOERROR with 0.0.0.0 / :: , or NODATA.
static size_t buildBlockedReply(const uint8_t *q, size_t qlen, size_t qEnd,
                                uint16_t qtype, uint8_t *out, size_t outCap) {
  if (qEnd > outCap) return 0;
  memcpy(out, q, qEnd);
  out[2] = 0x81; // QR=1, RD copied as 1
  out[3] = 0x80; // RA=1, RCODE=0
  out[4] = 0; out[5] = 1;  // QDCOUNT = 1
  out[6] = 0; out[7] = 0;  // ANCOUNT
  out[8] = 0; out[9] = 0;  // NSCOUNT
  out[10] = 0; out[11] = 0; // ARCOUNT
  size_t p = qEnd;

  auto putAnswer = [&](const uint8_t *rdata, uint16_t rdlen) {
    if (p + 12 + rdlen > outCap) return;
    out[p++] = 0xC0; out[p++] = 0x0C;                 // name -> offset 12
    out[p++] = (qtype >> 8) & 0xFF; out[p++] = qtype & 0xFF;
    out[p++] = 0x00; out[p++] = 0x01;                 // class IN
    out[p++] = 0; out[p++] = 0; out[p++] = 0; out[p++] = 60; // TTL 60s
    out[p++] = (rdlen >> 8) & 0xFF; out[p++] = rdlen & 0xFF;
    memcpy(out + p, rdata, rdlen); p += rdlen;
    out[6] = 0; out[7] = 1;
  };

  if (qtype == 1) { // A
    static const uint8_t zero4[4] = {0, 0, 0, 0};
    putAnswer(zero4, 4);
  } else if (qtype == 28) { // AAAA
    static const uint8_t zero16[16] = {0};
    putAnswer(zero16, 16);
  }
  // other qtypes: NOERROR / no answer (NODATA)
  return p;
}

// --------------------------- pending table ----------------------------------

static int allocPending(uint16_t origId, const IPAddress &ip, uint16_t port,
                        const uint8_t *q, size_t qlen, uint16_t &ourIdOut) {
  int slot = -1;
  portENTER_CRITICAL(&s_pendMux);
  for (size_t i = 0; i < MAX_PENDING; i++) {
    if (!s_pending[i].used) { slot = (int)i; break; }
  }
  if (slot < 0) {
    // table full: evict the oldest
    uint32_t oldest = UINT32_MAX;
    for (size_t i = 0; i < MAX_PENDING; i++) {
      if (s_pending[i].sentMs < oldest) { oldest = s_pending[i].sentMs; slot = (int)i; }
    }
  }
  Pending &e = s_pending[slot];
  e.used = true;
  e.origId = origId;
  e.ourId = s_nextId++;
  if (s_nextId == 0) s_nextId = 1;
  ourIdOut = e.ourId;
  e.clientIp = ip;
  e.clientPort = port;
  e.sentMs = millis();
  e.upstreamIdx = s_upstreamIdx;
  e.retried = false;
  e.qlen = (uint16_t)min(qlen, MAX_QUERY_COPY);
  memcpy(e.query, q, e.qlen);
  portEXIT_CRITICAL(&s_pendMux);
  return slot;
}

// --------------------------- packet handlers --------------------------------

static void handleUpstreamReply(AsyncUDPPacket &pkt) {
  const uint8_t *d = pkt.data();
  size_t len = pkt.length();
  if (len < 12) return;
  uint16_t id = (d[0] << 8) | d[1];

  Pending copy;
  bool found = false;
  portENTER_CRITICAL(&s_pendMux);
  for (size_t i = 0; i < MAX_PENDING; i++) {
    if (s_pending[i].used && s_pending[i].ourId == id) {
      copy = s_pending[i];
      s_pending[i].used = false;
      found = true;
      break;
    }
  }
  portEXIT_CRITICAL(&s_pendMux);
  if (!found) return;

  s_consecFail = 0;
  s_upHealthy = true;

  // restore the client's original transaction ID and relay it back
  static uint8_t out[1500];
  size_t n = min(len, sizeof(out));
  memcpy(out, d, n);
  out[0] = (copy.origId >> 8) & 0xFF;
  out[1] = copy.origId & 0xFF;
  s_srv.writeTo(out, n, copy.clientIp, copy.clientPort);
}

static void handleClientQuery(AsyncUDPPacket &pkt) {
  const uint8_t *d = pkt.data();
  size_t len = pkt.length();
  if (len < 12 || len > MAX_QUERY_COPY) {
    // oversized/short: just relay verbatim if we can, else ignore
    if (len >= 12 && len <= 1400) {
      s_up.writeTo(d, len, currentUpstream(), 53);
    }
    return;
  }
  if (!isLocalClient(pkt.remoteIP())) {
    s_stats.droppedNonLocal++;
    return;
  }

  s_stats.total++;

  uint16_t origId = (d[0] << 8) | d[1];
  String name;
  uint16_t qtype = 0;
  size_t qEnd = 0;
  bool parsed = parseQuestion(d, len, name, qtype, qEnd);

  if (parsed && DnsServer53::blockingActive() && Blocklist::isBlocked(name)) {
    static uint8_t rep[512];
    size_t n = buildBlockedReply(d, len, qEnd, qtype, rep, sizeof(rep));
    if (n) {
      s_srv.writeTo(rep, n, pkt.remoteIP(), pkt.remotePort());
      s_stats.blocked++;
      if (s_blockQ) {
        BlockMsg m;
        strncpy(m.domain, name.c_str(), sizeof(m.domain) - 1);
        m.domain[sizeof(m.domain) - 1] = 0;
        IPAddress ci = pkt.remoteIP();
        m.clientIp = (uint32_t)ci;
        xQueueSend(s_blockQ, &m, 0); // non-blocking; drop if full
      }
      return;
    }
    // if we somehow failed to build a reply, fall through and forward
  }

  // ---- forward upstream ----
  uint16_t ourId;
  allocPending(origId, pkt.remoteIP(), pkt.remotePort(), d, len, ourId);
  static uint8_t fwd[MAX_QUERY_COPY];
  memcpy(fwd, d, len);
  fwd[0] = (ourId >> 8) & 0xFF;
  fwd[1] = ourId & 0xFF;
  if (s_up.writeTo(fwd, len, currentUpstream(), 53)) {
    s_stats.forwarded++;
  } else {
    s_stats.upstreamErrors++;
  }
}

// --------------------------- lifecycle --------------------------------------

bool DnsServer53::begin() {
  if (!s_blockQ) s_blockQ = xQueueCreate(24, sizeof(BlockMsg));

  if (!s_up.listen(UPSTREAM_LOCAL_PORT)) {
    Logger::log("dns: failed to bind upstream socket");
    return false;
  }
  s_up.onPacket([](AsyncUDPPacket pkt) { handleUpstreamReply(pkt); });

  if (!s_srv.listen(DNS_PORT)) {
    Logger::log("dns: FAILED to bind UDP 53");
    return false;
  }
  s_srv.onPacket([](AsyncUDPPacket pkt) { handleClientQuery(pkt); });

  Logger::log("dns: listening on UDP 53, upstream " + activeUpstream());
  return true;
}

DnsStats DnsServer53::stats() { return s_stats; }

void DnsServer53::resetStats() {
  s_stats = DnsStats();
  s_recentBlocked.clear();
}

std::vector<BlockedEntry> DnsServer53::recentBlocked(size_t n) {
  if (s_recentBlocked.size() <= n) return s_recentBlocked;
  return std::vector<BlockedEntry>(s_recentBlocked.end() - n, s_recentBlocked.end());
}

void DnsServer53::loop() {
  // drain blocked-domain notifications
  if (s_blockQ) {
    BlockMsg m;
    while (xQueueReceive(s_blockQ, &m, 0) == pdTRUE) {
      BlockedEntry e;
      e.domain = String(m.domain);
      e.when = time(nullptr);
      e.client = IPAddress(m.clientIp).toString();
      s_recentBlocked.push_back(e);
      if (s_recentBlocked.size() > RECENT_MAX) s_recentBlocked.erase(s_recentBlocked.begin());
    }
  }

  // expire / retry pending upstream queries
  uint32_t now = millis();
  uint32_t timeout = ConfigStore::cfg.dns_timeout_ms;
  struct Retry { uint8_t buf[MAX_QUERY_COPY]; uint16_t len; };
  std::vector<Retry> retries;
  bool sawTimeout = false;
  int needRetryCount = 0;

  portENTER_CRITICAL(&s_pendMux);
  for (size_t i = 0; i < MAX_PENDING; i++) {
    Pending &e = s_pending[i];
    if (!e.used) continue;
    if (now - e.sentMs < timeout) continue;
    if (!e.retried) {
      e.retried = true;
      e.sentMs = now;
      needRetryCount++;
      Retry r;
      memcpy(r.buf, e.query, e.qlen);
      r.buf[0] = (e.ourId >> 8) & 0xFF;
      r.buf[1] = e.ourId & 0xFF;
      r.len = e.qlen;
      retries.push_back(r);
    } else {
      e.used = false;
      sawTimeout = true;
    }
  }
  portEXIT_CRITICAL(&s_pendMux);

  if (sawTimeout) s_stats.upstreamTimeouts++;

  // A query that needed a retry counts as a soft failure of the *current*
  // upstream, even though the retry itself succeeded. Without this a dead
  // primary is never rotated away and every lookup pays the timeout penalty.
  if (sawTimeout || needRetryCount) {
    if (s_consecFail < 255) s_consecFail++;
    if (s_consecFail >= 4) {
      s_upHealthy = false;
      rotateUpstream();
      s_consecFail = 0;
    }
  }

  // send retries on the *next* upstream, outside the critical section
  if (!retries.empty()) {
    IPAddress alt = currentUpstream();
    auto &v = ConfigStore::cfg.upstream_dns;
    if (v.size() > 1) {
      IPAddress a;
      if (a.fromString(v[(s_upstreamIdx + 1) % v.size()])) alt = a;
    }
    for (auto &r : retries) s_up.writeTo(r.buf, r.len, alt, 53);
  }
}
