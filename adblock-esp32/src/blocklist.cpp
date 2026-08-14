#include "blocklist.h"
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <LittleFS.h>
#include <esp_heap_caps.h>
#include <esp_task_wdt.h>
#include <algorithm>
#include <vector>
#include "config.h"
#include "logger.h"
#include "util_hash.h"

// ---------------------------------------------------------------------------
// Sorted uint64 hash table lives in PSRAM. Lookups are a binary search guarded
// by a spinlock. During a refresh the table pointer is set to null, which makes
// isBlocked() fail OPEN (nothing blocked) rather than blocking wrongly - a
// refresh must never be able to take the internet down.
// ---------------------------------------------------------------------------

static portMUX_TYPE s_tableMux = portMUX_INITIALIZER_UNLOCKED;
static uint64_t *s_table = nullptr;
static size_t s_count = 0;

static BlocklistStatus s_status;
static TaskHandle_t s_refreshTask = nullptr;
static uint32_t s_lastRefreshMs = 0;
static bool s_bootRefreshDone = false;

static std::vector<String> s_white;
static std::vector<String> s_black;

static const char *BL_PATH = "/blocklist.bin";
static const char *BL_TMP = "/blocklist.tmp";
// 700k domains = 5.6MB in PSRAM and 5.6MB on flash. Safe now that a refresh
// drops the stale boot cache when headroom is short, giving the temp file most
// of the 9.8MB LittleFS partition. PSRAM peak stays ~5.6MB of the free ~7.5MB
// because the old table is released before the new one is built.
static const size_t MAX_DOMAINS = 700000;
static const size_t MIN_SANE_DOMAINS = 1000; // refuse to swap in a suspiciously tiny list

// --------------------------- helpers ---------------------------------------

static bool suffixMatch(const String &domain, const String &entry) {
  if (domain == entry) return true;
  if (domain.length() > entry.length() &&
      domain.endsWith("." + entry))
    return true;
  return false;
}

static bool inList(const std::vector<String> &list, const String &domain) {
  for (const auto &e : list) {
    if (suffixMatch(domain, e)) return true;
  }
  return false;
}

// Parse one raw line from a hosts/domain/ABP-format blocklist into a domain.
// Returns empty String if the line yields nothing usable.
static String parseLine(char *line) {
  // strip CR and trailing whitespace
  size_t n = strlen(line);
  while (n && (line[n - 1] == '\r' || line[n - 1] == '\n' || line[n - 1] == ' ' ||
               line[n - 1] == '\t')) {
    line[--n] = 0;
  }
  char *p = line;
  while (*p == ' ' || *p == '\t') p++;
  if (!*p) return String();
  if (*p == '#' || *p == '!' || *p == ';') return String();

  String tok;

  // AdBlock Plus style: ||example.com^
  if (p[0] == '|' && p[1] == '|') {
    p += 2;
    char *caret = strchr(p, '^');
    if (caret) *caret = 0;
    tok = String(p);
  } else {
    // hosts style: "0.0.0.0 example.com" / "127.0.0.1 example.com"
    char *sp = strpbrk(p, " \t");
    if (sp) {
      *sp = 0;
      String first(p);
      if (first == "0.0.0.0" || first == "127.0.0.1" || first == "::1" ||
          first == "::" || first == "255.255.255.255") {
        char *q = sp + 1;
        while (*q == ' ' || *q == '\t') q++;
        // cut an inline comment / extra fields
        char *cut = strpbrk(q, " \t#");
        if (cut) *cut = 0;
        tok = String(q);
      } else {
        return String(); // unrecognised multi-field line
      }
    } else {
      tok = String(p); // bare domain list
    }
  }

  tok.trim();
  tok.toLowerCase();
  while (tok.endsWith(".")) tok.remove(tok.length() - 1);
  if (tok.isEmpty()) return String();
  if (tok.indexOf('.') < 0) return String(); // needs at least one dot
  if (tok.indexOf('/') >= 0 || tok.indexOf(' ') >= 0) return String();
  if (tok == "localhost" || tok == "localhost.localdomain" ||
      tok == "broadcasthost" || tok == "ip6-localhost" ||
      tok == "ip6-loopback" || tok == "0.0.0.0")
    return String();
  if (tok.length() > 253) return String();
  return tok;
}

// --------------------------- public API -------------------------------------

BlocklistStatus Blocklist::status() {
  BlocklistStatus s = s_status;
  portENTER_CRITICAL(&s_tableMux);
  s.domainCount = s_count;
  portEXIT_CRITICAL(&s_tableMux);
  return s;
}

void Blocklist::reloadOverrides() {
  s_white.clear();
  s_black.clear();
  for (auto &w : ConfigStore::cfg.whitelist) {
    String x = w;
    x.trim();
    x.toLowerCase();
    if (x.length()) s_white.push_back(x);
  }
  for (auto &b : ConfigStore::cfg.blacklist) {
    String x = b;
    x.trim();
    x.toLowerCase();
    if (x.length()) s_black.push_back(x);
  }
}

bool Blocklist::isBlocked(const String &domainLower) {
  // 1. explicit whitelist always wins (this is the user's escape hatch)
  if (inList(s_white, domainLower)) return false;
  // 2. explicit blacklist
  if (inList(s_black, domainLower)) return true;

  // 3. hash table lookup, walking up the label hierarchy so that
  //    a.b.doubleclick.net matches a doubleclick.net entry
  String d = domainLower;
  int guard = 0;
  while (guard++ < 8) {
    uint64_t h = fnv1a64(d);
    bool found = false;
    portENTER_CRITICAL(&s_tableMux);
    if (s_table && s_count) {
      size_t lo = 0, hi = s_count;
      while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        uint64_t v = s_table[mid];
        if (v == h) { found = true; break; }
        if (v < h) lo = mid + 1; else hi = mid;
      }
    }
    portEXIT_CRITICAL(&s_tableMux);
    if (found) return true;

    int dot = d.indexOf('.');
    if (dot < 0) break;
    // strip the leftmost label; stop once only a bare TLD-ish pair remains
    String next = d.substring(dot + 1);
    if (next.indexOf('.') < 0) break;
    d = next;
  }
  return false;
}

// ------------------------- persistence --------------------------------------

static bool loadTableFromFile(const char *path) {
  if (!LittleFS.exists(path)) return false;
  File f = LittleFS.open(path, "r");
  if (!f) return false;
  size_t bytes = f.size();
  size_t n = bytes / sizeof(uint64_t);
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
  reloadOverrides();
  if (loadTableFromFile(BL_PATH)) {
    s_status.lastUpdateOk = true;
    // recover last-update timestamp
    File f = LittleFS.open("/bl_meta.txt", "r");
    if (f) {
      s_status.lastUpdateEpoch = (time_t)f.readStringUntil('\n').toInt();
      f.close();
    }
  } else {
    Logger::log("bl: no usable stored blocklist; starting in pass-through until first refresh");
  }
}

// --------------------------- refresh ----------------------------------------

struct DlResult {
  size_t added = 0;
  bool ok = false;
  String err;
};

static DlResult downloadSource(const String &url, File &out) {
  DlResult r;
  WiFiClientSecure *secure = nullptr;
  HTTPClient http;
  http.setFollowRedirects(HTTPC_STRICT_FOLLOW_REDIRECTS);
  http.setTimeout(20000);
  http.setReuse(false);

  bool https = url.startsWith("https://");
  bool begun = false;
  if (https) {
    secure = new WiFiClientSecure();
    // Blocklists are public, non-secret content and we do not act on them as
    // code, so we accept the cert without pinning. Firmware (OTA) is a
    // different matter and IS verified by SHA-256 - see ota.cpp.
    secure->setInsecure();
    secure->setTimeout(20);
    begun = http.begin(*secure, url);
  } else {
    begun = http.begin(url);
  }
  if (!begun) {
    r.err = "begin failed";
    if (secure) delete secure;
    return r;
  }

  int code = http.GET();
  if (code != HTTP_CODE_OK) {
    r.err = "HTTP " + String(code);
    http.end();
    if (secure) delete secure;
    return r;
  }

  WiFiClient *stream = http.getStreamPtr();
  char lineBuf[300];
  size_t li = 0;
  uint8_t buf[1024];
  uint64_t hashBatch[256];
  size_t hb = 0;
  uint32_t lastData = millis();

  while (http.connected()) {
    size_t avail = stream->available();
    if (!avail) {
      if (millis() - lastData > 20000) { r.err = "stalled"; break; }
      delay(2);
      if (!stream->connected() && !stream->available()) break;
      continue;
    }
    lastData = millis();
    int got = stream->readBytes(buf, avail > sizeof(buf) ? sizeof(buf) : avail);
    for (int i = 0; i < got; i++) {
      char c = (char)buf[i];
      if (c == '\n') {
        lineBuf[li] = 0;
        String d = parseLine(lineBuf);
        li = 0;
        if (d.length()) {
          hashBatch[hb++] = fnv1a64(d);
          if (hb == 256) {
            size_t want = hb * sizeof(uint64_t);
            if (out.write((uint8_t *)hashBatch, want) != want) {
              // Almost always "filesystem full". Silently ignoring this is how
              // a refresh ends up quietly dropping an entire source.
              r.err = "write failed (filesystem full?)";
              http.end();
              if (secure) delete secure;
              return r;
            }
            r.added += hb;
            hb = 0;
          }
        }
      } else if (li < sizeof(lineBuf) - 1) {
        lineBuf[li++] = c;
      } else {
        li = 0; // overlong line, drop it
      }
    }
    vTaskDelay(1); // keep the scheduler happy during long downloads
  }
  // trailing partial line
  if (li) {
    lineBuf[li] = 0;
    String d = parseLine(lineBuf);
    if (d.length()) hashBatch[hb++] = fnv1a64(d);
  }
  if (hb) {
    size_t want = hb * sizeof(uint64_t);
    if (out.write((uint8_t *)hashBatch, want) != want) {
      r.err = "write failed (filesystem full?)";
      http.end();
      if (secure) delete secure;
      return r;
    }
    r.added += hb;
  }

  http.end();
  if (secure) delete secure;
  if (r.err.isEmpty()) r.ok = true;
  return r;
}

void Blocklist::refreshTask(void *param) {
  s_status.refreshInProgress = true;
  s_status.sourcesOk = 0;
  s_status.sourcesFailed = 0;
  s_status.lastError = "";
  Logger::log("bl: refresh starting");

  LittleFS.remove(BL_TMP);

  // The temp file and the previous boot cache have to coexist on a 9.8MB
  // partition. With modern lists that is genuinely tight, so if headroom is
  // short we drop the boot cache first: the live table is already in PSRAM, so
  // this costs nothing now, and the cache is rewritten at the end of a
  // successful refresh. Worst case (refresh fails AND power is lost) we boot
  // with no list and fail open until the next fetch - never a hard failure.
  {
    size_t total = LittleFS.totalBytes();
    size_t used = LittleFS.usedBytes();
    size_t freeB = total > used ? total - used : 0;
    Logger::log("bl: fs " + String(used / 1024) + "KB used / " + String(total / 1024) +
                "KB total (" + String(freeB / 1024) + "KB free)");
    if (freeB < 6UL * 1024 * 1024 && LittleFS.exists(BL_PATH)) {
      LittleFS.remove(BL_PATH);
      Logger::log("bl: dropped stale boot cache to make room for the rebuild");
    }
  }

  File out = LittleFS.open(BL_TMP, "w");
  if (!out) {
    s_status.lastError = "cannot open temp file";
    s_status.refreshInProgress = false;
    Logger::log("bl: " + s_status.lastError);
    s_refreshTask = nullptr;
    vTaskDelete(nullptr);
    return;
  }

  size_t total = 0;
  for (auto &url : ConfigStore::cfg.blocklist_urls) {
    if (WiFi.status() != WL_CONNECTED) {
      s_status.lastError = "wifi down during refresh";
      break;
    }
    Logger::log("bl: fetching " + url);
    DlResult r = downloadSource(url, out);
    if (r.ok) {
      s_status.sourcesOk++;
      total += r.added;
      Logger::log("bl:   +" + String(r.added) + " domains");
    } else {
      s_status.sourcesFailed++;
      s_status.lastError = url + ": " + r.err;
      Logger::log("bl:   FAILED " + r.err);
    }
    if (total >= MAX_DOMAINS) {
      Logger::log("bl: reached the " + String(MAX_DOMAINS) +
                  " domain cap after " + String(s_status.sourcesOk) +
                  " source(s); remaining sources skipped");
      s_status.lastError = "domain cap reached - later sources skipped";
      break;
    }
  }
  out.close();

  // ---- fail-safe: only replace the live table if the new list looks sane ----
  if (total < MIN_SANE_DOMAINS) {
    Logger::log("bl: refresh produced only " + String(total) +
                " domains - keeping previous list");
    if (s_status.lastError.isEmpty()) s_status.lastError = "too few domains";
    s_status.lastUpdateOk = false;
    LittleFS.remove(BL_TMP);
    s_status.refreshInProgress = false;
    s_lastRefreshMs = millis();
    s_refreshTask = nullptr;
    vTaskDelete(nullptr);
    return;
  }

  // ---- free the old table, then sort + dedupe the new one in PSRAM ----------
  // While s_table is null, isBlocked() returns false => pass-through. This is
  // the intended fail-open window (a few seconds, once a day).
  portENTER_CRITICAL(&s_tableMux);
  uint64_t *old = s_table;
  s_table = nullptr;
  s_count = 0;
  portEXIT_CRITICAL(&s_tableMux);
  if (old) heap_caps_free(old);

  // Ordering here matters for large lists. The temp file is deleted as soon as
  // it is in PSRAM, and the previous blocklist.bin is only replaced once the new
  // table is live - so at no point do we need room for three copies on flash,
  // and a failure at any step still leaves a recoverable state.
  File in = LittleFS.open(BL_TMP, "r");
  bool swapped = false;
  if (in) {
    size_t n = in.size() / sizeof(uint64_t);
    uint64_t *buf = (uint64_t *)heap_caps_malloc(n * sizeof(uint64_t), MALLOC_CAP_SPIRAM);
    if (buf) {
      size_t rd = in.read((uint8_t *)buf, n * sizeof(uint64_t));
      in.close();
      LittleFS.remove(BL_TMP); // reclaim the temp space immediately
      if (rd == n * sizeof(uint64_t)) {
        std::sort(buf, buf + n);
        size_t uniq = std::unique(buf, buf + n) - buf;
        Logger::log("bl: " + String(n) + " raw -> " + String(uniq) + " unique domains");

        // Bring the new table live BEFORE touching flash, so blocking resumes
        // at the earliest possible moment and a flash failure below only costs
        // us the boot cache, not the working list.
        portENTER_CRITICAL(&s_tableMux);
        s_table = buf;
        s_count = uniq;
        portEXIT_CRITICAL(&s_tableMux);
        swapped = true;

        LittleFS.remove(BL_PATH);
        File pf = LittleFS.open(BL_PATH, "w");
        if (pf) {
          // Write in modest chunks and yield between them. A single monolithic
          // multi-MB write holds the LittleFS lock long enough to starve the
          // main loop and trip the task watchdog.
          const size_t CH = 2048;
          size_t wrote = 0;
          for (size_t i = 0; i < uniq; i += CH) {
            size_t c = min(CH, uniq - i);
            wrote += pf.write((uint8_t *)(buf + i), c * sizeof(uint64_t));
            vTaskDelay(pdMS_TO_TICKS(2));
          }
          pf.close();
          if (wrote != uniq * sizeof(uint64_t)) {
            Logger::log("bl: WARNING - boot cache write short (" + String(wrote) +
                        " bytes); list is live in PSRAM but will need a refetch after reboot");
            LittleFS.remove(BL_PATH);
          }
        } else {
          Logger::log("bl: WARNING - could not persist boot cache; list is live in PSRAM only");
        }
      } else {
        heap_caps_free(buf);
        s_status.lastError = "short read building table";
      }
    } else {
      in.close();
      LittleFS.remove(BL_TMP);
      s_status.lastError = "PSRAM alloc failed (list too large?)";
    }
  }
  LittleFS.remove(BL_TMP);

  if (swapped) {
    s_status.lastUpdateOk = true;
    s_status.lastUpdateEpoch = time(nullptr);
    File mf = LittleFS.open("/bl_meta.txt", "w");
    if (mf) { mf.println((long)s_status.lastUpdateEpoch); mf.close(); }
    Logger::log("bl: refresh complete, " + String(s_count) + " domains active");
  } else {
    s_status.lastUpdateOk = false;
    Logger::log("bl: refresh failed to build table (" + s_status.lastError +
                "); attempting to reload previous stored list");
    loadTableFromFile(BL_PATH); // best effort recovery
  }

  s_status.refreshInProgress = false;
  s_lastRefreshMs = millis();
  s_refreshTask = nullptr;
  vTaskDelete(nullptr);
}

void Blocklist::requestRefresh() {
  if (s_refreshTask != nullptr || s_status.refreshInProgress) {
    Logger::log("bl: refresh already running");
    return;
  }
  if (WiFi.status() != WL_CONNECTED) {
    Logger::log("bl: refresh skipped, wifi down");
    return;
  }
  // Big stack: TLS + parsing. Pinned to core 0 to keep core 1 free for DNS.
  xTaskCreatePinnedToCore(Blocklist::refreshTask, "bl_refresh", 16384, nullptr, 1,
                          &s_refreshTask, 0);
}

void Blocklist::loopMaintenance() {
  if (WiFi.status() != WL_CONNECTED) return;
  if (s_status.refreshInProgress) return;

  // first refresh shortly after boot if we have no list at all
  if (!s_bootRefreshDone) {
    portENTER_CRITICAL(&s_tableMux);
    size_t c = s_count;
    portEXIT_CRITICAL(&s_tableMux);
    if (c == 0 && millis() > 8000) {
      s_bootRefreshDone = true;
      Logger::log("bl: no list present, doing initial fetch");
      requestRefresh();
      return;
    }
    if (millis() > 20000) s_bootRefreshDone = true;
  }

  uint32_t intervalMs = ConfigStore::cfg.refresh_interval_hours * 3600UL * 1000UL;
  if (intervalMs == 0) return;
  if (s_lastRefreshMs == 0) {
    // schedule relative to boot if we loaded a stored list
    s_lastRefreshMs = millis();
    return;
  }
  if (millis() - s_lastRefreshMs > intervalMs) {
    Logger::log("bl: scheduled refresh due");
    requestRefresh();
  }
}
