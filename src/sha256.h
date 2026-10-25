// SPDX-License-Identifier: MIT
// Copyright (c) 1993-1994, 2026 Andy van Wezel

#pragma once

#include <cstddef>
#include <cstdint>

struct Sha256 {
  uint32_t h[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
  uint8_t buf[64];
  uint64_t total = 0;
  size_t fill = 0;

  void update(const uint8_t *p, size_t n);
  void final(uint8_t out[32]);

private:
  void block(const uint8_t *p);
};

// Keeps the padded key states so PBKDF2 pays two compressions per iteration less.
struct Hmac {
  Sha256 inner, outer;

  Hmac(const uint8_t *key, size_t klen);
  void mac(const uint8_t *msg, size_t n, uint8_t out[32]) const;
};
