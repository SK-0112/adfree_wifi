#pragma once
// Blocklist line parser. Plain C so it can be unit-tested off the device
// (see test/test_parse.cpp).
#include <stddef.h>
#include <string.h>

static inline bool hostChar(char c) {
  return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_';
}

// Parse one line of a hosts file, plain domain list or AdGuard/ABP list into a
// lowercase domain written to `out`. Returns its length, or 0 to skip the line.
//
// Deliberate choices for DNS-level lists:
//  * `@@` exception rules are skipped, not honoured. In AdGuard Home they
//    un-block real ad domains other lists block (cdn.taboola.com,
//    www.googleadservices.com). The allowlist is the escape hatch here.
//  * Rules with modifiers other than $important are skipped: $badfilter,
//    $client, $dnstype, $denyallow are conditional and must not become
//    unconditional blocks (`||pl.ua^$badfilter` would block all of .pl.ua).
//  * Wildcards other than a leading "*." are skipped.
static inline size_t parseLine(char *p, char *out, size_t cap) {
  while (*p == ' ' || *p == '\t') p++;
  if (!*p || *p == '#' || *p == '!' || *p == ';' || *p == '[') return 0;
  if (p[0] == '@' && p[1] == '@') return 0;

  char *tok;
  if (*p == '|') {
    p += (p[1] == '|') ? 2 : 1;
    char *dollar = strchr(p, '$');
    if (dollar) {
      *dollar = 0;
      char *mods = dollar + 1;
      size_t ml = strlen(mods);
      while (ml && (mods[ml - 1] == ' ' || mods[ml - 1] == '\t')) mods[--ml] = 0;
      if (strcmp(mods, "important") != 0) return 0;
    }
    char *caret = strchr(p, '^');
    if (caret) *caret = 0;
    size_t l = strlen(p);
    while (l && p[l - 1] == '|') p[--l] = 0;
    tok = p;
  } else {
    char *sp = strpbrk(p, " \t");
    if (sp) {
      *sp = 0;
      if (!strcmp(p, "0.0.0.0") || !strcmp(p, "127.0.0.1") || !strcmp(p, "::") ||
          !strcmp(p, "::1") || !strcmp(p, "255.255.255.255")) {
        tok = sp + 1;
        while (*tok == ' ' || *tok == '\t') tok++;
        char *cut = strpbrk(tok, " \t#");
        if (cut) *cut = 0;
      } else {
        // a bare domain followed by a comment is still a domain
        char *rest = sp + 1;
        while (*rest == ' ' || *rest == '\t') rest++;
        if (*rest && *rest != '#') return 0;
        tok = p;
      }
    } else {
      tok = p;
    }
  }

  if (tok[0] == '*' && tok[1] == '.') tok += 2;
  size_t n = 0;
  bool dot = false, alpha = false;
  for (char *c = tok; *c; c++) {
    char ch = *c;
    if (ch >= 'A' && ch <= 'Z') ch += 32;
    if (!hostChar(ch)) return 0; // '*', '/', '^', '@', non-ASCII...
    if (n + 1 >= cap) return 0;
    if (ch == '.') dot = true;
    else if (!(ch >= '0' && ch <= '9')) alpha = true;
    out[n++] = ch;
  }
  while (n && out[n - 1] == '.') n--;
  out[n] = 0;
  if (!n || n > 253 || !dot || !alpha || out[0] == '.') return 0; // need a dot; skip bare IPs
  if (!strcmp(out, "localhost.localdomain") || !strcmp(out, "local")) return 0;
  return n;
}

// Offsets of the suffixes a lookup checks, most specific first:
// "a.b.example.com" -> a.b.example.com, b.example.com, example.com. The bare
// TLD is left out, so a list entry for "com" can never block everything.
// Returns how many offsets were written (at least 1).
static inline int domainSuffixes(const char *name, size_t len, size_t *offs, int max) {
  // Very deep names keep their last `max` levels: those are the ones that
  // reach the registrable domain a list is likely to name.
  int labels = 1;
  for (size_t i = 0; i + 1 < len; i++)
    if (name[i] == '.') labels++;
  int skip = labels > max ? labels - max : 0;
  int n = 0;
  if (!skip) offs[n++] = 0;
  for (size_t i = 0; i + 1 < len && n < max; i++) {
    if (name[i] != '.') continue;
    if (skip > 1) { skip--; continue; }
    if (skip == 1) { skip = 0; }
    offs[n++] = i + 1;
  }
  return n > 1 ? n - 1 : 1;
}
