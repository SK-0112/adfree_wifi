#pragma once
#include <stddef.h>
#include <stdint.h>

// FNV-1a 64-bit: fast, good distribution for domain-name hashing.
static inline uint64_t fnv1a64(const char *s, size_t n) {
  uint64_t h = 14695981039346656037ULL;
  for (size_t i = 0; i < n; i++) {
    h ^= (uint8_t)s[i];
    h *= 1099511628211ULL;
  }
  return h;
}

#ifdef ARDUINO
#include <Arduino.h>
static inline uint64_t fnv1a64(const String &s) { return fnv1a64(s.c_str(), s.length()); }
#endif
