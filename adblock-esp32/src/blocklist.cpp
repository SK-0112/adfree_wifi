#include "blocklist.h"
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <LittleFS.h>
#include <ArduinoJson.h>
#include <esp_heap_caps.h>
#include <algorithm>
#include <atomic>
#include <vector>
#include "config.h"
#include "logger.h"
#include "util_hash.h"
#include "list_parse.h"

// ---------------------------------------------------------------------------
// Sorted uint64 hash table in PSRAM, binary-searched under a spinlock. The
// user's allow/deny lists are hash tables too, so a lookup never allocates and
// never walks a list of strings.
//
// A refresh builds the new table next to the old one when PSRAM allows. When
// it doesn't, the old table is freed first and lookups pass everything through
// for the few seconds the sort takes: a refresh must never be able to take the
// internet down.
// ---------------------------------------------------------------------------

static portMUX_TYPE s_tableMux = portMUX_INITIALIZER_UNLOCKED;
static uint64_t *s_table = nullptr;
static size_t s_count = 0;
static std::vector<uint64_t> *s_allow = new std::vector<uint64_t>();
static std::vector<uint64_t> *s_deny = new std::vector<uint64_t>();

// Status is written by the refresh task and read by the web and main loop, and
// it holds Strings, so it gets a real mutex.
static SemaphoreHandle_t s_stMux = nullptr;
static BlocklistStatus s_status;

static std::atomic<bool> s_running(false);
static TaskHandle_t s_refreshTask = nullptr;

// Scheduling. Everything is relative to the age of the list on flash, so a
// board that reboots daily still refreshes daily.
static uint32_t s_lastAttemptMs = 0;
static bool s_attempted = false;
static uint32_t s_retryAtMs = 0; // non-zero: a failed refresh is waiting for its retry
static uint8_t s_failStreak = 0;
static uint8_t s_partialStreak = 0;

static const char *BL_PATH = "/blocklist.bin";
static const char *BL_TMP = "/blocklist.tmp";
static const char *META_PATH = "/bl_meta.json";
// 700k raw entries = 5.6MB of PSRAM while sorting. The defaults come to about
// 640k raw and 490k after de-duplication.
static const size_t MAX_DOMAINS = 700000;
static const size_t MIN_SANE_DOMAINS = 1000; // refuse to swap in a suspiciously tiny list
static const uint32_t BOOT_SETTLE_MS = 45000;  // let Wi-Fi, NTP and DNS come up first
static const uint32_t MIN_GAP_MS = 5UL * 60UL * 1000UL;

static void stLock() { xSemaphoreTake(s_stMux, portMAX_DELAY); }
static void stUnlock() { xSemaphoreGive(s_stMux); }

// --------------------------- lookup -----------------------------------------

static inline bool sortedHas(const uint64_t *t, size_t n, uint64_t h) {
  size_t lo = 0, hi = n;
  while (lo < hi) {
    size_t mid = lo + (hi - lo) / 2;
    uint64_t v = t[mid];
    if (v == h) return true;
    if (v < h) lo = mid + 1; else hi = mid;
  }
  return false;
}

Verdict Blocklist::check(const char *name, size_t len, size_t *matchOff) {
  if (!len) return Verdict::NONE;
  // Suffix offsets, most specific first: a.b.example.com, b.example.com,
  // example.com. The bare TLD is never checked.
  static const int MAXL = 24;
  size_t offs[MAXL];
  int levels = domainSuffixes(name, len, offs, MAXL);
  uint64_t h[MAXL];
  for (int k = 0; k < levels; k++) h[k] = fnv1a64(name + offs[k], len - offs[k]);

  Verdict v = Verdict::NONE;
  int hit = -1;
  portENTER_CRITICAL(&s_tableMux);
  // The user's own lists first. The most specific entry wins, and at the same
  // level allow beats deny: allow example.com + deny ads.example.com blocks
  // ads.example.com and nothing else.
  const uint64_t *a = s_allow->data(), *d = s_deny->data();
  size_t an = s_allow->size(), dn = s_deny->size();
  for (int k = 0; k < levels && v == Verdict::NONE; k++) {
    if (an && sortedHas(a, an, h[k])) { v = Verdict::ALLOW; hit = k; }
    else if (dn && sortedHas(d, dn, h[k])) { v = Verdict::DENY; hit = k; }
  }
  if (v == Verdict::NONE && s_table && s_count) {
    for (int k = 0; k < levels; k++) {
      if (sortedHas(s_table, s_count, h[k])) { v = Verdict::LIST; hit = k; break; }
    }
  }
  portEXIT_CRITICAL(&s_tableMux);
  if (matchOff && hit >= 0) *matchOff = offs[hit];
  return v;
}

static std::vector<uint64_t> *buildHashSet(const std::vector<String> &src) {
  auto *v = new std::vector<uint64_t>();
  v->reserve(src.size());
  for (auto &e : src) {
    String x = e;
    x.trim();
    x.toLowerCase();
    while (x.endsWith(".")) x.remove(x.length() - 1);
    if (x.startsWith("*.")) x.remove(0, 2);
    if (x.length()) v->push_back(fnv1a64(x));
  }
  std::sort(v->begin(), v->end());
  v->erase(std::unique(v->begin(), v->end()), v->end());
  return v;
}

void Blocklist::reloadOverrides() {
  std::vector<uint64_t> *na, *nd;
  {
    CfgLock g;
    na = buildHashSet(ConfigStore::cfg.whitelist);
    nd = buildHashSet(ConfigStore::cfg.blacklist);
  }
  portENTER_CRITICAL(&s_tableMux);
  std::swap(na, s_allow);
  std::swap(nd, s_deny);
  portEXIT_CRITICAL(&s_tableMux);
  delete na; // old tables: no reader can hold them once the swap is done
  delete nd;
}

// --------------------------- public API -------------------------------------

static int32_t secondsUntilDue() {
  if (s_running) return 0;
  uint32_t ms = millis();
  if (s_retryAtMs) return (int32_t)(s_retryAtMs - ms) > 0 ? (int32_t)((s_retryAtMs - ms) / 1000) : 0;
  int64_t interval = (int64_t)ConfigStore::cfg.refresh_interval_hours * 3600;
  time_t now = time(nullptr);
  time_t last;
  stLock();
  last = s_status.lastUpdateEpoch;
  stUnlock();
  int64_t due;
  if (now > 1700000000 && last > 1700000000) due = (int64_t)last + interval - now;
  else if (s_attempted) due = interval - (int64_t)((ms - s_lastAttemptMs) / 1000);
  else due = interval - ms / 1000;
  if (due < 0) due = 0;
  if (due > interval) due = interval; // clock went backwards
  return (int32_t)due;
}

BlocklistStatus Blocklist::status() {
  stLock();
  BlocklistStatus s = s_status;
  stUnlock();
  portENTER_CRITICAL(&s_tableMux);
  s.domainCount = s_count;
  portEXIT_CRITICAL(&s_tableMux);
  s.capacity = MAX_DOMAINS;
  s.refreshInProgress = s_running;
  s.nextRefreshSecs = secondsUntilDue();
  return s;
}

// ------------------------- persistence --------------------------------------

static void saveMeta() {
  JsonDocument doc;
  stLock();
  doc["epoch"] = (long)s_status.lastUpdateEpoch;
  JsonArray a = doc["sources"].to<JsonArray>();
  for (auto &s : s_status.sources) {
    JsonObject o = a.add<JsonObject>();
    o["u"] = s.url;
    o["ok"] = s.ok;
    o["n"] = s.entries;
    if (s.err.length()) o["e"] = s.err;
  }
  stUnlock();
  File f = LittleFS.open(META_PATH, "w");
  if (f) { serializeJson(doc, f); f.close(); }
}

static void loadMeta() {
  File f = LittleFS.open(META_PATH, "r");
  if (!f) {
    // 1.0.x kept only the timestamp in a text file
    File old = LittleFS.open("/bl_meta.txt", "r");
    if (old) {
      long e = old.readStringUntil('\n').toInt();
      old.close();
      stLock();
      s_status.lastUpdateEpoch = e;
      stUnlock();
    }
    return;
  }
  JsonDocument doc;
  bool ok = !deserializeJson(doc, f);
  f.close();
  if (!ok) return;
  stLock();
  s_status.lastUpdateEpoch = doc["epoch"] | 0L;
  s_status.sources.clear();
  for (JsonObjectConst o : doc["sources"].as<JsonArrayConst>()) {
    SourceResult r;
    r.url = o["u"] | "";
    r.ok = o["ok"] | false;
    r.entries = o["n"] | 0;
    r.err = o["e"] | "";
    if (r.ok) s_status.sourcesOk++; else s_status.sourcesFailed++;
    s_status.sources.push_back(r);
  }
  stUnlock();
}

static bool persistTable(const uint64_t *buf, size_t n) {
  LittleFS.remove(BL_PATH);
  File pf = LittleFS.open(BL_PATH, "w");
  if (!pf) return false;
  // Modest chunks with a yield between them. One multi-MB write holds the
  // LittleFS lock long enough to starve everything else.
  const size_t CH = 2048;
  size_t wrote = 0;
  for (size_t i = 0; i < n; i += CH) {
    size_t c = std::min(CH, n - i);
    wrote += pf.write((const uint8_t *)(buf + i), c * sizeof(uint64_t));
    vTaskDelay(pdMS_TO_TICKS(2));
  }
  pf.close();
  if (wrote != n * sizeof(uint64_t)) {
    LittleFS.remove(BL_PATH);
    return false;
  }
  return true;
}

static bool loadTableFromFile(const char *path) {
  File f = LittleFS.open(path, "r");
  if (!f) return false;
  size_t n = f.size() / sizeof(uint64_t);
  if (n == 0 || n > MAX_DOMAINS) {
    f.close();
    Logger::log("bl: stored table size implausible, ignoring");
    return false;
  }
  uint64_t *buf = (uint64_t *)heap_caps_malloc(n * sizeof(uint64_t), MALLOC_CAP_SPIRAM);
  if (!buf) {
    f.close();
    Logger::log("bl: PSRAM alloc failed for " + String(n) + " domains");
    return false;
  }
  size_t rd = f.read((uint8_t *)buf, n * sizeof(uint64_t));
  f.close();
  if (rd != n * sizeof(uint64_t)) {
    heap_caps_free(buf);
    Logger::log("bl: short read on stored table");
    return false;
  }
  portENTER_CRITICAL(&s_tableMux);
  uint64_t *old = s_table;
  s_table = buf;
  s_count = n;
  portEXIT_CRITICAL(&s_tableMux);
  if (old) heap_caps_free(old);
  Logger::log("bl: loaded " + String(n) + " domains into PSRAM");
  return true;
}

void Blocklist::begin() {
  if (!s_stMux) s_stMux = xSemaphoreCreateMutex();
  reloadOverrides();
  LittleFS.remove(BL_TMP); // leftover from a refresh interrupted by power loss
  loadMeta();
  if (loadTableFromFile(BL_PATH)) {
    stLock();
    s_status.lastUpdateOk = true;
    stUnlock();
  } else {
    Logger::log("bl: no usable stored blocklist; passing lookups through until the first download");
  }
}

// --------------------------- refresh ----------------------------------------

struct DlResult {
  size_t added = 0;
  bool ok = false;
  String err;
};

static DlResult downloadSource(const String &url, File &out, size_t budget) {
  DlResult r;
  WiFiClientSecure *secure = nullptr;
  HTTPClient http;
  http.setFollowRedirects(HTTPC_STRICT_FOLLOW_REDIRECTS);
  http.setTimeout(20000);
  http.setReuse(false);
  // HTTP/1.0 rules out chunked transfer encoding. getStreamPtr() hands us the
  // raw socket, so chunk-size lines would otherwise be spliced into the data
  // and could turn "0.0.0.0 ads.google.com" into a bare "google.com".
  http.useHTTP10(true);

  bool begun;
  if (url.startsWith("https://")) {
    secure = new WiFiClientSecure();
    // Blocklists are public data we never execute, so the certificate is not
    // pinned. The worst a tampered list can do is block or miss domains; the
    // size floor below rejects an emptied one. Firmware is verified (ota.cpp).
    secure->setInsecure();
    secure->setTimeout(20);
    begun = http.begin(*secure, url);
  } else {
    begun = http.begin(url);
  }
  if (!begun) {
    r.err = "bad URL";
    delete secure;
    return r;
  }
  http.addHeader("Accept-Encoding", "identity");

  int code = http.GET();
  if (code != HTTP_CODE_OK) {
    r.err = code < 0 ? String(HTTPClient::errorToString(code)) : "HTTP " + String(code);
    http.end();
    delete secure;
    return r;
  }

  int expected = http.getSize(); // -1 when the server didn't say
  WiFiClient *stream = http.getStreamPtr();
  char lineBuf[512];
  char dom[256];
  size_t li = 0;
  bool skipping = false; // inside an overlong line: drop it through to the newline
  uint8_t buf[1460];
  uint64_t hashBatch[256];
  size_t hb = 0;
  size_t readTotal = 0;
  uint32_t lastData = millis();
  bool capped = false;

  auto flush = [&]() -> bool {
    if (!hb) return true;
    size_t want = hb * sizeof(uint64_t);
    if (out.write((uint8_t *)hashBatch, want) != want) {
      r.err = "flash full";
      return false;
    }
    r.added += hb;
    hb = 0;
    return true;
  };
  auto takeLine = [&]() -> bool {
    lineBuf[li] = 0;
    li = 0;
    if (r.added + hb >= budget) { capped = true; return true; }
    size_t n = parseLine(lineBuf, dom, sizeof(dom));
    if (n) {
      hashBatch[hb++] = fnv1a64(dom, n);
      if (hb == 256 && !flush()) return false;
    }
    return true;
  };

  while (!capped) {
    size_t avail = stream->available();
    if (!avail) {
      if (expected >= 0 && readTotal >= (size_t)expected) break;
      if (!stream->connected()) break;
      if (millis() - lastData > 20000) { r.err = "download stalled"; break; }
      vTaskDelay(pdMS_TO_TICKS(5));
      continue;
    }
    lastData = millis();
    int got = stream->readBytes(buf, avail > sizeof(buf) ? sizeof(buf) : avail);
    if (got <= 0) continue;
    readTotal += got;
    for (int i = 0; i < got && !capped; i++) {
      char c = (char)buf[i];
      if (c == '\n') {
        if (skipping) { skipping = false; li = 0; continue; }
        if (li && lineBuf[li - 1] == '\r') li--;
        if (!takeLine()) { http.end(); delete secure; return r; }
      } else if (!skipping) {
        if (li < sizeof(lineBuf) - 1) lineBuf[li++] = c;
        else { skipping = true; li = 0; }
      }
    }
    vTaskDelay(1); // let the scheduler breathe during long downloads
  }
  if (li && !skipping && !capped) {
    if (lineBuf[li - 1] == '\r') li--;
    takeLine();
  }
  if (!flush()) { http.end(); delete secure; return r; }
  http.end();
  delete secure;

  if (r.err.isEmpty() && expected >= 0 && readTotal < (size_t)expected && !capped)
    r.err = "download cut short (" + String(readTotal) + " of " + String(expected) + " bytes)";
  if (capped) Logger::log("bl:   capacity reached, rest of this list skipped");
  if (r.err.isEmpty()) r.ok = true;
  return r;
}

static void finishRun(bool success) {
  s_lastAttemptMs = millis();
  s_attempted = true;
  if (success) {
    s_failStreak = 0;
    s_retryAtMs = 0;
  } else {
    // 10 min, 20, 40, 80, then every 3 h (or the interval, if shorter)
    if (s_failStreak < 8) s_failStreak++;
    uint32_t backoff = 10UL * 60UL * 1000UL << std::min<uint8_t>(s_failStreak - 1, 3);
    uint32_t cap = std::min<uint32_t>(3UL * 3600UL * 1000UL, ConfigStore::cfg.refresh_interval_hours * 3600UL * 1000UL);
    if (backoff > cap) backoff = cap;
    s_retryAtMs = millis() + backoff;
    if (s_retryAtMs == 0) s_retryAtMs = 1;
    Logger::log("bl: will retry in " + String(backoff / 60000) + " min");
  }
}

void Blocklist::refreshTask(void *param) {
  std::vector<String> urls;
  {
    CfgLock g;
    urls = ConfigStore::cfg.blocklist_urls;
  }
  Logger::log("bl: refresh starting (" + String(urls.size()) + " lists)");
  std::vector<SourceResult> results;
  String lastErr;

  LittleFS.remove(BL_TMP);
  // The temp file and the boot cache have to share the ~9.8MB partition. If
  // headroom is short, drop the boot cache: the live table is already in
  // PSRAM, and the cache is rewritten at the end either way.
  bool droppedCache = false;
  {
    size_t total = LittleFS.totalBytes(), used = LittleFS.usedBytes();
    size_t freeB = total > used ? total - used : 0;
    if (freeB < 6UL * 1024 * 1024 && LittleFS.exists(BL_PATH)) {
      LittleFS.remove(BL_PATH);
      droppedCache = true;
    }
  }

  size_t total = 0;
  uint32_t okCount = 0, failCount = 0;
  File out = LittleFS.open(BL_TMP, "w");
  if (!out) {
    lastErr = "cannot open temp file";
  } else {
    for (auto &url : urls) {
      SourceResult sr;
      sr.url = url;
      if (WiFi.status() != WL_CONNECTED) {
        sr.err = "Wi-Fi down";
        failCount++;
        lastErr = sr.err;
        results.push_back(sr);
        continue;
      }
      if (total >= MAX_DOMAINS) {
        sr.err = "skipped: memory full";
        failCount++;
        results.push_back(sr);
        continue;
      }
      Logger::log("bl: fetching " + url);
      size_t before = out.size();
      DlResult r = downloadSource(url, out, MAX_DOMAINS - total);
      sr.entries = r.added;
      if (r.ok) {
        sr.ok = true;
        okCount++;
        total += r.added;
        Logger::log("bl:   +" + String(r.added) + " entries");
      } else {
        // Throw away whatever this source wrote. A half-downloaded list is
        // still mostly fine, but its tail is gone and we want a clean retry.
        out.seek(before);
        sr.err = r.err;
        failCount++;
        lastErr = url + ": " + r.err;
        Logger::log("bl:   FAILED " + r.err);
      }
      results.push_back(sr);
    }
    out.close();
  }

  size_t have;
  portENTER_CRITICAL(&s_tableMux);
  have = s_count;
  portEXIT_CRITICAL(&s_tableMux);

  // ---- decide whether the new list is good enough to replace the old ------
  bool keepOld = false;
  if (total < MIN_SANE_DOMAINS) {
    keepOld = true;
    if (lastErr.isEmpty()) lastErr = "lists produced only " + String(total) + " entries";
  } else if (failCount && have && s_partialStreak < 2) {
    // Swapping now would silently drop every domain only the failed list had.
    // Keep the complete old list and retry; after three partial runs in a row
    // accept what we have, so one dead URL can't freeze updates forever.
    keepOld = true;
    s_partialStreak++;
  }

  bool swapped = false;
  if (!keepOld) {
    File in = LittleFS.open(BL_TMP, "r");
    size_t n = in ? std::min(in.size() / sizeof(uint64_t), MAX_DOMAINS) : 0;
    if (n) {
      // Build beside the old table when PSRAM allows, so blocking never pauses.
      size_t need = n * sizeof(uint64_t);
      bool roomForBoth = heap_caps_get_largest_free_block(MALLOC_CAP_SPIRAM) > need + 256 * 1024;
      if (!roomForBoth) {
        portENTER_CRITICAL(&s_tableMux);
        uint64_t *old = s_table;
        s_table = nullptr;
        s_count = 0;
        portEXIT_CRITICAL(&s_tableMux);
        if (old) heap_caps_free(old);
        Logger::log("bl: not enough PSRAM for two tables; passing lookups through while sorting");
      }
      uint64_t *buf = (uint64_t *)heap_caps_malloc(need, MALLOC_CAP_SPIRAM);
      if (buf) {
        size_t rd = in.read((uint8_t *)buf, need);
        in.close();
        LittleFS.remove(BL_TMP); // reclaim the space before writing the cache
        if (rd == need) {
          std::sort(buf, buf + n);
          size_t uniq = std::unique(buf, buf + n) - buf;
          uint64_t *shrunk = (uint64_t *)heap_caps_realloc(buf, uniq * sizeof(uint64_t), MALLOC_CAP_SPIRAM);
          if (shrunk) buf = shrunk;
          Logger::log("bl: " + String(n) + " entries -> " + String(uniq) + " unique domains");
          portENTER_CRITICAL(&s_tableMux);
          uint64_t *old = s_table;
          s_table = buf;
          s_count = uniq;
          portEXIT_CRITICAL(&s_tableMux);
          if (old) heap_caps_free(old);
          swapped = true;
          if (!persistTable(buf, uniq))
            Logger::log("bl: WARNING - could not write the boot cache; list is live in PSRAM only");
        } else {
          heap_caps_free(buf);
          lastErr = "short read building table";
        }
      } else {
        in.close();
        lastErr = "not enough PSRAM for the list";
      }
    } else {
      if (in) in.close();
      lastErr = "temp file missing";
    }
  }
  LittleFS.remove(BL_TMP);

  if (!swapped && droppedCache) {
    // We dropped the boot cache to make room. Put the live table back on
    // flash, or the next reboot would start with no list at all.
    portENTER_CRITICAL(&s_tableMux);
    uint64_t *t = s_table;
    size_t c = s_count;
    portEXIT_CRITICAL(&s_tableMux);
    if (t && c) persistTable(t, c);
    else loadTableFromFile(BL_PATH);
  }
  if (!swapped && !have) loadTableFromFile(BL_PATH);

  stLock();
  s_status.sourcesOk = okCount;
  s_status.sourcesFailed = failCount;
  s_status.lastError = lastErr;
  if (swapped) {
    s_status.lastUpdateOk = true;
    s_status.lastUpdateEpoch = time(nullptr);
    s_status.sources = results;
  } else {
    s_status.lastUpdateOk = false;
    // keep the per-source counts of the list that is actually live, but show
    // which downloads failed this time
    for (auto &r : results) {
      bool found = false;
      for (auto &s : s_status.sources)
        if (s.url == r.url) { found = true; if (!r.ok) { s.ok = false; s.err = r.err; } }
      if (!found) s_status.sources.push_back(r);
    }
  }
  stUnlock();
  saveMeta();

  if (swapped) {
    s_partialStreak = 0;
    Logger::log("bl: refresh complete, " + String(s_count) + " domains active");
    finishRun(failCount == 0);
  } else {
    Logger::log("bl: keeping the previous list (" + (lastErr.length() ? lastErr : String("a list failed")) + ")");
    finishRun(false);
  }

  s_refreshTask = nullptr;
  s_running = false;
  vTaskDelete(nullptr);
}

void Blocklist::requestRefresh() {
  if (WiFi.status() != WL_CONNECTED) {
    Logger::log("bl: refresh skipped, Wi-Fi down");
    return;
  }
  bool expected = false;
  if (!s_running.compare_exchange_strong(expected, true)) {
    Logger::log("bl: refresh already running");
    return;
  }
  s_lastAttemptMs = millis();
  s_attempted = true;
  s_retryAtMs = 0;
  // Big stack for TLS + parsing. Core 0, leaving core 1 to the network tasks.
  if (xTaskCreatePinnedToCore(Blocklist::refreshTask, "bl_refresh", 16384, nullptr, 1,
                              &s_refreshTask, 0) != pdPASS) {
    s_running = false;
    Logger::log("bl: could not start refresh task (low memory)");
  }
}

void Blocklist::loopMaintenance() {
  if (WiFi.status() != WL_CONNECTED || s_running) return;
  uint32_t ms = millis();
  if (ms < BOOT_SETTLE_MS) return;
  if (s_attempted && ms - s_lastAttemptMs < MIN_GAP_MS) return;

  size_t c;
  portENTER_CRITICAL(&s_tableMux);
  c = s_count;
  portEXIT_CRITICAL(&s_tableMux);
  if (c == 0 && !s_attempted) {
    Logger::log("bl: no list present, doing initial download");
    requestRefresh();
    return;
  }
  // Wait for NTP before judging a stored list's age, unless we never will.
  time_t last;
  stLock();
  last = s_status.lastUpdateEpoch;
  stUnlock();
  bool clockOk = time(nullptr) > 1700000000;
  if (!clockOk && last > 1700000000 && ms < 10UL * 60UL * 1000UL) return;

  if (secondsUntilDue() <= 0) {
    Logger::log(s_retryAtMs ? "bl: retrying failed refresh" : "bl: scheduled refresh due");
    requestRefresh();
  }
}
