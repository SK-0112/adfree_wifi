#pragma once
#include <Arduino.h>

// FNV-1a 64-bit — fast, good distribution for domain-name hashing.
static inline uint64_t fnv1a64(const String &s) {
  uint64_t h = 14695981039346656037ULL;
  for (size_t i = 0; i < s.length(); i++) {
    h ^= (uint8_t)s[i];
    h *= 1099511628211ULL;
  }
  return h;
}
