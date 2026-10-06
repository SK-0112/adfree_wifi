#include "dns_server.h"
#include <WiFi.h>
#include <AsyncUDP.h>
#include <esp_random.h>
#include <esp_timer.h>
#include <esp_heap_caps.h>
#include <freertos/queue.h>
#include <algorithm>
#include "config.h"
#include "blocklist.h"
#include "logger.h"

// ---------------------------------------------------------------------------
// UDP/53 resolver.
//
//  * Queries are answered from the AsyncUDP task. That path does no heap
//    allocation and never touches ConfigStore: upstreams are copied into a
//    small array by applyConfig().
//  * Allowed queries are relayed upstream under a random transaction ID. A
//    reply is accepted only from the server it was sent to, on port 53, with a
//    matching ID, so another host on the LAN can't inject answers.
//  * Anything that goes wrong (no blocklist, paused, disabled, odd packet)
//    results in the query being FORWARDED, never dropped. The failure mode of
//    this device is "acts like a plain DNS relay", not "internet is down".
// ---------------------------------------------------------------------------

static const uint16_t DNS_PORT = 53;
static const uint16_t UPSTREAM_LOCAL_PORT = 5333;
static const size_t MAX_PENDING = 64;
static const size_t MAX_QUERY = 512;
static const size_t MAX_UPSTREAMS = 4;
static const uint16_t EDNS_MAX_UDP = 1232; // avoids IP fragmentation, which lwIP here can't reassemble
static const size_t RING_SIZE = 120;
static const size_t TOP_K = 48;
static const size_t MAX_CLIENTS = 64;

struct Pending {
  bool used;
  bool retried;
  uint16_t origId;
  uint16_t ourId;
  uint32_t clientIp;
  uint16_t clientPort;
  uint32_t sentMs;
  uint32_t sentTo[2]; // first try, retry
  uint16_t qlen;
  uint8_t query[MAX_QUERY];
};

static AsyncUDP s_srv;
static AsyncUDP s_up;
static Pending *s_pending = nullptr; // PSRAM, 64 x ~530 B
static portMUX_TYPE s_pendMux = portMUX_INITIALIZER_UNLOCKED;

static portMUX_TYPE s_upMux = portMUX_INITIALIZER_UNLOCKED;
static uint32_t s_ups[MAX_UPSTREAMS];
static uint8_t s_upCount = 0;
static uint8_t s_upIdx = 0;
static uint8_t s_consecFail = 0;
static volatile bool s_upHealthy = true;

static volatile uint32_t s_myIp = 0, s_myMask = 0;

static portMUX_TYPE s_statMux = portMUX_INITIALIZER_UNLOCKED;
static DnsStats s_stats;
static uint32_t s_histQ[HISTORY_BUCKETS], s_histB[HISTORY_BUCKETS];
static uint32_t s_histBucket = 0; // absolute bucket number (uptime / step) of the newest slot

// Query-log events go to the main loop through a queue so the UDP task never
// allocates. Under a flood the queue drops entries; counters stay exact.
struct QMsg {
  char domain[96];
  uint32_t client;
  uint16_t qtype;
  uint8_t verdict;
};
static QueueHandle_t s_qQ = nullptr;

static SemaphoreHandle_t s_logMux = nullptr; // guards ring, top, clients
static QueryEntry *s_ring = nullptr;
static size_t s_ringHead = 0, s_ringLen = 0;
struct TopSlot { char domain[96]; uint32_t count; };
static TopSlot s_top[TOP_K];
static size_t s_topLen = 0;
static ClientStat s_clients[MAX_CLIENTS];
static size_t s_clientLen = 0;

// --------------------------- helpers ---------------------------------------

uint32_t DnsServer53::uptimeSec() { return (uint32_t)(esp_timer_get_time() / 1000000ULL); }

void DnsServer53::applyConfig() {
  uint32_t tmp[MAX_UPSTREAMS];
  uint8_t n = 0;
  uint32_t me = (uint32_t)WiFi.localIP();
  {
    CfgLock g;
    for (auto &s : ConfigStore::cfg.upstream_dns) {
      IPAddress ip;
      if (n >= MAX_UPSTREAMS || !ip.fromString(s)) continue;
      uint32_t v = (uint32_t)ip;
      // Forwarding to ourselves would loop forever; 0.0.0.0 goes nowhere.
      if (v == 0 || v == me || v == 0xFFFFFFFF) continue;
      tmp[n++] = v;
    }
  }
  if (n == 0) { tmp[0] = (uint32_t)IPAddress(1, 1, 1, 1); tmp[1] = (uint32_t)IPAddress(9, 9, 9, 9); n = 2; }
  portENTER_CRITICAL(&s_upMux);
  memcpy(s_ups, tmp, sizeof(tmp));
  s_upCount = n;
  s_upIdx = 0;
  s_consecFail = 0;
  portEXIT_CRITICAL(&s_upMux);
  s_upHealthy = true;
}

static uint32_t upstreamAt(int offset) {
  portENTER_CRITICAL(&s_upMux);
  uint32_t v = s_upCount ? s_ups[(s_upIdx + offset) % s_upCount] : (uint32_t)IPAddress(1, 1, 1, 1);
  portEXIT_CRITICAL(&s_upMux);
  return v;
}

static void rotateUpstream() {
  uint32_t now;
  bool rotated = false;
  portENTER_CRITICAL(&s_upMux);
  if (s_upCount > 1) { s_upIdx = (s_upIdx + 1) % s_upCount; rotated = true; }
  now = s_ups[s_upIdx];
  portEXIT_CRITICAL(&s_upMux);
  if (rotated) Logger::log("dns: switching upstream to " + IPAddress(now).toString());
}

bool DnsServer53::upstreamHealthy() { return s_upHealthy; }
String DnsServer53::activeUpstream() { return IPAddress(upstreamAt(0)).toString(); }

bool DnsServer53::blockingActive() {
  const AppConfig &c = ConfigStore::cfg;
  if (!c.enabled || c.pause_indefinite) return false;
  if (c.pause_until_epoch) {
    time_t now = time(nullptr);
    // No clock yet: honour the pause the user asked for until NTP says it's over.
    if (now < 1700000000) return false;
    if ((uint32_t)now < c.pause_until_epoch) return false;
  }
  return true;
}

// Only answer clients on our own LAN, so that if this device is ever exposed
// it can't be used as an open resolver or DNS amplifier.
static inline bool isLocalClient(uint32_t ip) {
  uint32_t me = s_myIp, mask = s_myMask;
  if (!me || !mask) return true; // address not known yet: don't drop the house
  return (ip & mask) == (me & mask);
}

// Parse the single question at offset 12 into a lowercase name.
static bool parseQuestion(const uint8_t *b, size_t len, char *name, size_t &nlen,
                          uint16_t &qtype, size_t &qEnd) {
  size_t off = 12, n = 0;
  for (int labels = 0; labels < 127; labels++) {
    if (off >= len) return false;
    uint8_t l = b[off++];
    if (l == 0) {
      if (off + 4 > len || n == 0) return false;
      qtype = (b[off] << 8) | b[off + 1];
      qEnd = off + 4;
      name[n] = 0;
      nlen = n;
      return true;
    }
    if (l > 63 || off + l > len) return false; // also rejects compression (0xC0)
    if (n + l + 1 > 253) return false;
    if (n) name[n++] = '.';
    for (uint8_t i = 0; i < l; i++) {
      char c = (char)b[off + i];
      if (c >= 'A' && c <= 'Z') c += 32;
      name[n++] = c;
    }
    off += l;
  }
  return false;
}

// Names that switch features off when they don't resolve. Answering NXDOMAIN
// makes Firefox keep using this resolver instead of its built-in DNS-over-HTTPS,
// and makes iPhones/Macs drop iCloud Private Relay on this network. Both would
// otherwise send lookups around the blocker.
static bool isCanary(const char *n) {
  return !strcmp(n, "use-application-dns.net") || !strcmp(n, "mask.icloud.com") ||
         !strcmp(n, "mask-h2.icloud.com");
}

// Build a reply in `out`: A -> 0.0.0.0, AAAA -> ::, anything else NODATA. With
// nxdomain, RCODE 3. Negative answers carry an SOA so clients cache them.
static size_t buildBlockedReply(const uint8_t *q, size_t qEnd, uint16_t qtype, bool nxdomain,
                                uint8_t *out, size_t cap) {
  if (qEnd + 64 > cap) return 0;
  memcpy(out, q, qEnd);
  out[2] = 0x80 | (q[2] & 0x01);       // QR=1, opcode 0, RD copied from the query
  out[3] = 0x80 | (nxdomain ? 3 : 0);  // RA=1
  out[4] = 0; out[5] = 1;
  memset(out + 6, 0, 6);
  size_t p = qEnd;
  auto put16 = [&](uint16_t v) { out[p++] = v >> 8; out[p++] = v & 0xFF; };
  auto put32 = [&](uint32_t v) { put16(v >> 16); put16(v & 0xFFFF); };

  if (!nxdomain && (qtype == 1 || qtype == 28)) {
    uint16_t rdlen = qtype == 1 ? 4 : 16;
    put16(0xC00C); put16(qtype); put16(1); put32(60); put16(rdlen);
    memset(out + p, 0, rdlen);
    p += rdlen;
    out[7] = 1; // ANCOUNT
  } else {
    // SOA in the authority section: name = the question, MNAME/RNAME root,
    // MINIMUM 60 s (the negative-cache TTL).
    put16(0xC00C); put16(6); put16(1); put32(60); put16(22);
    out[p++] = 0; out[p++] = 0;  // MNAME ".", RNAME "."
    put32(1); put32(3600); put32(600); put32(86400); put32(60);
    out[9] = 1; // NSCOUNT
  }
  return p;
}

// Cap the EDNS UDP payload size a client advertises. Upstream answers bigger
// than one packet would arrive fragmented and be dropped here; at 1232 bytes
// the upstream truncates instead and the client retries properly.
static void clampEdns(uint8_t *q, size_t len, size_t qEnd) {
  if (q[6] || q[7] || q[8] || q[9] || q[10] != 0 || q[11] != 1) return; // only "question + OPT"
  if (qEnd + 11 > len || q[qEnd] != 0 || q[qEnd + 1] != 0 || q[qEnd + 2] != 41) return;
  uint16_t sz = (q[qEnd + 3] << 8) | q[qEnd + 4];
  if (sz > EDNS_MAX_UDP) { q[qEnd + 3] = EDNS_MAX_UDP >> 8; q[qEnd + 4] = EDNS_MAX_UDP & 0xFF; }
}

// Move the newest history slot up to `bucket`, zeroing the slots skipped over.
// Caller holds s_statMux.
static void advanceBuckets(uint32_t bucket) {
  if (bucket == s_histBucket) return;
  uint32_t gap = bucket - s_histBucket;
  if (gap >= HISTORY_BUCKETS) {
    memset(s_histQ, 0, sizeof(s_histQ));
    memset(s_histB, 0, sizeof(s_histB));
  } else {
    for (uint32_t i = 1; i <= gap; i++) {
      size_t k = (s_histBucket + i) % HISTORY_BUCKETS;
      s_histQ[k] = 0;
      s_histB[k] = 0;
    }
  }
  s_histBucket = bucket;
}

static void histAdd(bool blocked) {
  uint32_t bucket = DnsServer53::uptimeSec() / HISTORY_STEP_S;
  portENTER_CRITICAL(&s_statMux);
  advanceBuckets(bucket);
  size_t k = bucket % HISTORY_BUCKETS;
  s_histQ[k]++;
  if (blocked) s_histB[k]++;
  s_stats.total++;
  if (blocked) s_stats.blocked++;
  portEXIT_CRITICAL(&s_statMux);
}

static inline void statInc(uint32_t DnsStats::*field) {
  portENTER_CRITICAL(&s_statMux);
  s_stats.*field += 1;
  portEXIT_CRITICAL(&s_statMux);
}

static void logQuery(const char *name, uint32_t client, uint16_t qtype, Verdict v) {
  if (!s_qQ) return;
  QMsg m;
  strncpy(m.domain, name, sizeof(m.domain) - 1);
  m.domain[sizeof(m.domain) - 1] = 0;
  m.client = client;
  m.qtype = qtype;
  m.verdict = (uint8_t)v;
  xQueueSend(s_qQ, &m, 0); // never block the DNS path
}

// --------------------------- pending table ----------------------------------

static uint16_t allocPending(uint16_t origId, uint32_t ip, uint16_t port, const uint8_t *q,
                             size_t qlen, uint32_t upstream) {
  portENTER_CRITICAL(&s_pendMux);
  int slot = -1;
  uint32_t oldestAge = 0;
  uint32_t now = millis();
  for (size_t i = 0; i < MAX_PENDING; i++) {
    if (!s_pending[i].used) { slot = (int)i; break; }
    uint32_t age = now - s_pending[i].sentMs;
    if (age >= oldestAge) { oldestAge = age; slot = (int)i; }
  }
  // Random ID, unique among in-flight queries. Sequential IDs make spoofed
  // answers easy to guess.
  uint16_t id;
  bool clash;
  do {
    id = (uint16_t)esp_random();
    clash = false;
    for (size_t i = 0; i < MAX_PENDING; i++)
      if (s_pending[i].used && s_pending[i].ourId == id) { clash = true; break; }
  } while (clash);
  Pending &e = s_pending[slot];
  e.used = true;
  e.retried = false;
  e.origId = origId;
  e.ourId = id;
  e.clientIp = ip;
  e.clientPort = port;
  e.sentMs = now;
  e.sentTo[0] = upstream;
  e.sentTo[1] = 0;
  e.qlen = (uint16_t)qlen;
  memcpy(e.query, q, qlen);
  portEXIT_CRITICAL(&s_pendMux);
  return id;
}

// --------------------------- packet handlers --------------------------------

static void handleUpstreamReply(AsyncUDPPacket &pkt) {
  const uint8_t *d = pkt.data();
  size_t len = pkt.length();
  if (len < 12 || !(d[2] & 0x80) || pkt.remotePort() != 53) return;
  uint16_t id = (d[0] << 8) | d[1];
  uint32_t from = (uint32_t)pkt.remoteIP();

  bool found = false;
  uint16_t origId = 0, cport = 0;
  uint32_t cip = 0;
  portENTER_CRITICAL(&s_pendMux);
  for (size_t i = 0; i < MAX_PENDING; i++) {
    Pending &e = s_pending[i];
    if (e.used && e.ourId == id && (from == e.sentTo[0] || from == e.sentTo[1])) {
      origId = e.origId;
      cip = e.clientIp;
      cport = e.clientPort;
      e.used = false;
      found = true;
      break;
    }
  }
  portEXIT_CRITICAL(&s_pendMux);
  if (!found) return;

  s_consecFail = 0;
  s_upHealthy = true;

  static uint8_t out[1500]; // only ever touched from the AsyncUDP task
  size_t n = len;
  if (n > sizeof(out)) {
    n = sizeof(out);
  }
  memcpy(out, d, n);
  if (n < len) out[2] |= 0x02; // set TC so the client knows it was cut
  out[0] = origId >> 8;
  out[1] = origId & 0xFF;
  s_srv.writeTo(out, n, IPAddress(cip), cport);
}

static void handleClientQuery(AsyncUDPPacket &pkt) {
  const uint8_t *d = pkt.data();
  size_t len = pkt.length();
  uint32_t cip = (uint32_t)pkt.remoteIP();
  if (len < 12) return;
  if (!isLocalClient(cip)) {
    statInc(&DnsStats::droppedNonLocal);
    return;
  }
  if (d[2] & 0x80) return; // a response, not a query

  static uint8_t buf[MAX_QUERY];
  static uint8_t rep[MAX_QUERY + 64];
  if (len > MAX_QUERY) {
    // Too big to copy; answer FORMERR rather than leave the client waiting.
    memcpy(rep, d, 12);
    rep[2] = 0x80 | (d[2] & 0x01);
    rep[3] = 0x81;
    memset(rep + 4, 0, 8);
    s_srv.writeTo(rep, 12, pkt.remoteIP(), pkt.remotePort());
    statInc(&DnsStats::upstreamErrors);
    return;
  }
  memcpy(buf, d, len);

  uint16_t origId = (buf[0] << 8) | buf[1];
  char name[256];
  size_t nlen = 0, qEnd = 0;
  uint16_t qtype = 0;
  bool standard = ((buf[2] >> 3) & 0x0F) == 0 && buf[4] == 0 && buf[5] == 1;
  bool parsed = standard && parseQuestion(buf, len, name, nlen, qtype, qEnd);

  Verdict v = Verdict::NONE;
  if (parsed && DnsServer53::blockingActive()) {
    v = Blocklist::check(name, nlen);
    if (v == Verdict::NONE && isCanary(name)) v = Verdict::LIST;
  }
  if (parsed) {
    bool blocked = v == Verdict::LIST || v == Verdict::DENY;
    histAdd(blocked);
    logQuery(name, cip, qtype, v);
    if (blocked) {
      size_t n = buildBlockedReply(buf, qEnd, qtype, isCanary(name), rep, sizeof(rep));
      if (n) {
        s_srv.writeTo(rep, n, pkt.remoteIP(), pkt.remotePort());
        return;
      }
      // couldn't build a reply: fall through and forward
    }
    clampEdns(buf, len, qEnd);
  } else {
    histAdd(false);
  }

  // ---- forward upstream ----
  uint32_t up = upstreamAt(0);
  uint16_t ourId = allocPending(origId, cip, pkt.remotePort(), buf, len, up);
  buf[0] = ourId >> 8;
  buf[1] = ourId & 0xFF;
  if (s_up.writeTo(buf, len, IPAddress(up), 53)) statInc(&DnsStats::forwarded);
  else statInc(&DnsStats::upstreamErrors);
}

// --------------------------- lifecycle --------------------------------------

bool DnsServer53::begin() {
  if (!s_qQ) s_qQ = xQueueCreate(64, sizeof(QMsg));
  if (!s_logMux) s_logMux = xSemaphoreCreateMutex();
  if (!s_pending) {
    s_pending = (Pending *)heap_caps_calloc(MAX_PENDING, sizeof(Pending), MALLOC_CAP_SPIRAM);
    if (!s_pending) s_pending = (Pending *)calloc(MAX_PENDING, sizeof(Pending));
  }
  if (!s_ring) {
    s_ring = (QueryEntry *)heap_caps_calloc(RING_SIZE, sizeof(QueryEntry), MALLOC_CAP_SPIRAM);
    if (!s_ring) s_ring = (QueryEntry *)calloc(RING_SIZE, sizeof(QueryEntry));
  }
  if (!s_pending || !s_ring) {
    Logger::log("dns: out of memory");
    return false;
  }
  s_myIp = (uint32_t)WiFi.localIP();
  s_myMask = (uint32_t)WiFi.subnetMask();
  applyConfig();

  if (!s_up.connected() && !s_up.listen(UPSTREAM_LOCAL_PORT)) {
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

DnsStats DnsServer53::stats() {
  portENTER_CRITICAL(&s_statMux);
  DnsStats s = s_stats;
  portEXIT_CRITICAL(&s_statMux);
  return s;
}

void DnsServer53::resetStats() {
  portENTER_CRITICAL(&s_statMux);
  s_stats = DnsStats();
  memset(s_histQ, 0, sizeof(s_histQ));
  memset(s_histB, 0, sizeof(s_histB));
  portEXIT_CRITICAL(&s_statMux);
  if (!s_logMux) return;
  xSemaphoreTake(s_logMux, portMAX_DELAY);
  s_ringHead = s_ringLen = 0;
  s_topLen = 0;
  s_clientLen = 0;
  xSemaphoreGive(s_logMux);
}

History DnsServer53::history() {
  History h;
  uint32_t up = uptimeSec();
  uint32_t bucket = up / HISTORY_STEP_S;
  portENTER_CRITICAL(&s_statMux);
  advanceBuckets(bucket); // a quiet stretch still has to show up as empty bars
  for (size_t i = 0; i < HISTORY_BUCKETS; i++) {
    size_t k = (bucket + 1 + i) % HISTORY_BUCKETS; // oldest first
    h.q[i] = s_histQ[k];
    h.b[i] = s_histB[k];
  }
  portEXIT_CRITICAL(&s_statMux);
  h.ageInBucket = up % HISTORY_STEP_S;
  return h;
}

std::vector<QueryEntry> DnsServer53::recentQueries(size_t n) {
  std::vector<QueryEntry> out;
  if (!s_logMux || !s_ring) return out;
  xSemaphoreTake(s_logMux, portMAX_DELAY);
  size_t m = std::min(n, s_ringLen);
  out.reserve(m);
  for (size_t i = 0; i < m; i++) out.push_back(s_ring[(s_ringHead + RING_SIZE - 1 - i) % RING_SIZE]);
  xSemaphoreGive(s_logMux);
  return out;
}

std::vector<TopDomain> DnsServer53::topBlocked(size_t n) {
  std::vector<TopDomain> out;
  if (!s_logMux) return out;
  xSemaphoreTake(s_logMux, portMAX_DELAY);
  std::vector<TopSlot> tmp(s_top, s_top + s_topLen);
  xSemaphoreGive(s_logMux);
  std::sort(tmp.begin(), tmp.end(), [](const TopSlot &a, const TopSlot &b) { return a.count > b.count; });
  for (size_t i = 0; i < tmp.size() && i < n; i++) out.push_back({String(tmp[i].domain), tmp[i].count});
  return out;
}

std::vector<ClientStat> DnsServer53::topClients(size_t n) {
  std::vector<ClientStat> out;
  if (!s_logMux) return out;
  xSemaphoreTake(s_logMux, portMAX_DELAY);
  out.assign(s_clients, s_clients + s_clientLen);
  xSemaphoreGive(s_logMux);
  std::sort(out.begin(), out.end(), [](const ClientStat &a, const ClientStat &b) { return a.queries > b.queries; });
  if (out.size() > n) out.resize(n);
  return out;
}

size_t DnsServer53::activeClients(uint32_t withinSec) {
  if (!s_logMux) return 0;
  uint32_t now = uptimeSec();
  size_t c = 0;
  xSemaphoreTake(s_logMux, portMAX_DELAY);
  for (size_t i = 0; i < s_clientLen; i++)
    if (now - s_clients[i].lastSeen <= withinSec) c++;
  xSemaphoreGive(s_logMux);
  return c;
}

static void recordQuery(const QMsg &m) {
  uint32_t now = DnsServer53::uptimeSec();
  bool blocked = m.verdict == (uint8_t)Verdict::LIST || m.verdict == (uint8_t)Verdict::DENY;
  xSemaphoreTake(s_logMux, portMAX_DELAY);
  QueryEntry &e = s_ring[s_ringHead];
  memcpy(e.domain, m.domain, sizeof(e.domain));
  e.client = m.client;
  e.uptime = now;
  e.qtype = m.qtype;
  e.verdict = m.verdict;
  s_ringHead = (s_ringHead + 1) % RING_SIZE;
  if (s_ringLen < RING_SIZE) s_ringLen++;

  // Busiest devices: evict the one idle longest when the table is full.
  size_t ci = s_clientLen;
  for (size_t i = 0; i < s_clientLen; i++) if (s_clients[i].ip == m.client) { ci = i; break; }
  if (ci == s_clientLen) {
    if (s_clientLen < MAX_CLIENTS) s_clientLen++;
    else {
      ci = 0;
      for (size_t i = 1; i < MAX_CLIENTS; i++) if (s_clients[i].lastSeen < s_clients[ci].lastSeen) ci = i;
    }
    s_clients[ci] = {m.client, 0, 0, now};
  }
  s_clients[ci].queries++;
  if (blocked) s_clients[ci].blocked++;
  s_clients[ci].lastSeen = now;

  // Most-blocked domains: space-saving top-k. Exact for anything that stays
  // in the table; a newcomer inherits the evicted slot's count as an upper bound.
  if (blocked) {
    size_t ti = s_topLen;
    for (size_t i = 0; i < s_topLen; i++) if (!strcmp(s_top[i].domain, m.domain)) { ti = i; break; }
    if (ti < s_topLen) s_top[ti].count++;
    else if (s_topLen < TOP_K) {
      memcpy(s_top[s_topLen].domain, m.domain, sizeof(m.domain));
      s_top[s_topLen++].count = 1;
    } else {
      size_t mi = 0;
      for (size_t i = 1; i < TOP_K; i++) if (s_top[i].count < s_top[mi].count) mi = i;
      memcpy(s_top[mi].domain, m.domain, sizeof(m.domain));
      s_top[mi].count++;
    }
  }
  xSemaphoreGive(s_logMux);
}

void DnsServer53::loop() {
  // refresh our own address once a second for the LAN check
  static uint32_t lastAddr = 0;
  if (millis() - lastAddr > 1000) {
    lastAddr = millis();
    s_myIp = (uint32_t)WiFi.localIP();
    s_myMask = (uint32_t)WiFi.subnetMask();
  }

  if (s_qQ) {
    QMsg m;
    int budget = 64;
    while (budget-- && xQueueReceive(s_qQ, &m, 0) == pdTRUE) recordQuery(m);
  }

  // expire / retry pending upstream queries
  uint32_t timeout = ConfigStore::cfg.dns_timeout_ms;
  uint32_t alt = upstreamAt(1);
  uint8_t retryIdx[MAX_PENDING];
  size_t nRetry = 0;
  bool sawTimeout = false;

  portENTER_CRITICAL(&s_pendMux);
  uint32_t now = millis(); // read inside the lock so no entry is newer than `now`
  for (size_t i = 0; i < MAX_PENDING; i++) {
    Pending &e = s_pending[i];
    if (!e.used || now - e.sentMs < timeout) continue;
    if (!e.retried) {
      e.retried = true;
      e.sentMs = now;
      e.sentTo[1] = alt;
      retryIdx[nRetry++] = (uint8_t)i;
    } else {
      e.used = false;
      sawTimeout = true;
    }
  }
  portEXIT_CRITICAL(&s_pendMux);

  if (sawTimeout) statInc(&DnsStats::upstreamTimeouts);

  // A query that needed a retry counts against the current upstream, even if
  // the retry worked. Otherwise a dead primary is never rotated away and every
  // lookup pays the timeout.
  if (sawTimeout || nRetry) {
    if (s_consecFail < 255) s_consecFail++;
    if (s_consecFail >= 4) {
      s_upHealthy = false;
      rotateUpstream();
      s_consecFail = 0;
    }
  }

  // Send retries to the next upstream, outside the critical section.
  static uint8_t rbuf[MAX_QUERY];
  for (size_t r = 0; r < nRetry; r++) {
    size_t len = 0;
    portENTER_CRITICAL(&s_pendMux);
    Pending &e = s_pending[retryIdx[r]];
    if (e.used && e.retried) {
      len = e.qlen;
      memcpy(rbuf, e.query, len);
      rbuf[0] = e.ourId >> 8;
      rbuf[1] = e.ourId & 0xFF;
    }
    portEXIT_CRITICAL(&s_pendMux);
    if (len) s_up.writeTo(rbuf, len, IPAddress(alt), 53);
  }
}
