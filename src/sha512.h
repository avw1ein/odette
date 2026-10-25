// SPDX-License-Identifier: MIT
// Copyright (c) 1993-1994, 2026 Andy van Wezel

#pragma once

#include <cstddef>
#include <cstdint>

struct Sha512 {
  uint64_t h[8] = { 0x6a09e667f3bcc908ull, 0xbb67ae8584caa73bull, 0x3c6ef372fe94f82bull, 0xa54ff53a5f1d36f1ull,
                    0x510e527fade682d1ull, 0x9b05688c2b3e6c1full, 0x1f83d9abfb41bd6bull, 0x5be0cd19137e2179ull };
  uint8_t buf[128];
  uint64_t total = 0;
  size_t fill = 0;

  void update(const uint8_t *p, size_t n);
  void final(uint8_t out[64]);

private:
  void block(const uint8_t *p);
};

struct Hmac512 {
  Sha512 inner, outer;

  Hmac512(const uint8_t *key, size_t klen);
  void mac(const uint8_t *msg, size_t n, uint8_t out[64]) const;
};
