// Host-side tests for the blocklist parser and suffix walk.
//
//   g++ -std=c++17 -O2 -I../src test_parse.cpp -o test_parse && ./test_parse [list files...]
//
// With list files it also parses each one the way the board does and prints
// how many entries it kept, which is a quick way to vet a new list.
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <unordered_set>
#include "list_parse.h"
#include "util_hash.h"

static int fails = 0;

static std::string parse(const char *line) {
  char buf[600], out[256];
  strncpy(buf, line, sizeof(buf) - 1);
  buf[sizeof(buf) - 1] = 0;
  size_t n = parseLine(buf, out, sizeof(out));
  return n ? std::string(out, n) : std::string();
}

static void expect(const char *line, const char *want) {
  std::string got = parse(line);
  if (got != want) {
    printf("FAIL parse(\"%s\") = \"%s\", want \"%s\"\n", line, got.c_str(), want);
    fails++;
  }
}

static std::vector<std::string> suffixes(const char *name) {
  size_t offs[24];
  int n = domainSuffixes(name, strlen(name), offs, 24);
  std::vector<std::string> v;
  for (int i = 0; i < n; i++) v.push_back(name + offs[i]);
  return v;
}

static void expectSuffixes(const char *name, std::vector<std::string> want) {
  auto got = suffixes(name);
  if (got != want) {
    printf("FAIL suffixes(%s):", name);
    for (auto &s : got) printf(" [%s]", s.c_str());
    printf("\n");
    fails++;
  }
}

int main(int argc, char **argv) {
  // AdGuard / ABP
  expect("||doubleclick.net^", "doubleclick.net");
  expect("||Ads.Example.COM^", "ads.example.com");
  expect("||ads.example.com^$important", "ads.example.com");
  expect("||pl.ua^$badfilter", "");
  expect("||example.org^$client=192.168.0.5", "");
  expect("||example.org^$dnstype=AAAA", "");
  expect("||example.org^$denyallow=foo.com", "");
  expect("@@||www.googleadservices.com^|", "");
  expect("@@|cdn.taboola.com^|", "");
  expect("|cdn.taboola.com^|", "cdn.taboola.com");
  expect("||ads*.example.com^", "");
  expect("||*.tracker.example^", "tracker.example");
  expect("/banner[0-9]+/", "");
  expect("! comment", "");
  expect("[Adblock Plus 2.0]", "");
  expect("example.com##.ad", "");
  // hosts
  expect("0.0.0.0 ads.example.com", "ads.example.com");
  expect("127.0.0.1\tads.example.com  # tracker", "ads.example.com");
  expect("0.0.0.0 0.0.0.0", "");
  expect("127.0.0.1 localhost", "");
  expect("192.168.1.1 router.lan", "");
  expect("::1 ip6-localhost", "");
  // plain domains
  expect("ads.example.com", "ads.example.com");
  expect("ads.example.com.", "ads.example.com");
  expect("ads.example.com # inline comment", "ads.example.com");
  expect("ads.example.com extra", "");
  expect("# hosts comment", "");
  expect("   ", "");
  expect("1.2.3.4", "");
  expect("localhost", "");
  expect("xn--80ak6aa92e.com", "xn--80ak6aa92e.com");
  expect("bad_domain.example.com", "bad_domain.example.com");
  expect("caf\xc3\xa9.example.com", "");

  expectSuffixes("a.b.example.com", {"a.b.example.com", "b.example.com", "example.com"});
  expectSuffixes("example.com", {"example.com"});
  expectSuffixes("localhost", {"localhost"});
  {
    // 30 labels: the walk must still reach doubleclick.net
    std::string deep;
    for (int i = 0; i < 28; i++) deep += "x" + std::to_string(i) + ".";
    deep += "doubleclick.net";
    auto s = suffixes(deep.c_str());
    if (s.empty() || s.back() != "doubleclick.net" || s.size() != 23) {
      printf("FAIL deep name: %zu levels, last [%s]\n", s.size(), s.empty() ? "" : s.back().c_str());
      fails++;
    }
  }

  // Real lists: report what the board would keep.
  for (int i = 1; i < argc; i++) {
    FILE *f = fopen(argv[i], "rb");
    if (!f) { printf("cannot open %s\n", argv[i]); fails++; continue; }
    char line[512], out[256];
    size_t lines = 0, kept = 0, overlong = 0;
    std::unordered_set<uint64_t> uniq;
    while (fgets(line, sizeof(line), f)) {
      size_t l = strlen(line);
      if (l && line[l - 1] != '\n' && !feof(f)) { // overlong: skip the rest, like the board
        overlong++;
        int c;
        while ((c = fgetc(f)) != EOF && c != '\n') {}
        continue;
      }
      while (l && (line[l - 1] == '\n' || line[l - 1] == '\r')) line[--l] = 0;
      lines++;
      size_t n = parseLine(line, out, sizeof(out));
      if (n) { kept++; uniq.insert(fnv1a64(out, n)); }
    }
    fclose(f);
    printf("%-60s lines %7zu  kept %7zu  unique %7zu  overlong %zu\n", argv[i], lines, kept, uniq.size(), overlong);
  }

  if (fails) { printf("%d FAILED\n", fails); return 1; }
  printf("all parser tests passed\n");
  return 0;
}
