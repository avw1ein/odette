// SPDX-License-Identifier: MIT
// Copyright (c) 1993-1994, 2026 Andy van Wezel

#include "sha256.h"

#include <algorithm>
#include <cstring>

namespace {

const uint32_t K256[64] = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

inline uint32_t rotr32(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

}  // namespace

void Sha256::block(const uint8_t *p)
{
  uint32_t w[64];
  for (int i = 0; i < 16; i++)
    w[i] = (uint32_t)p[4 * i] << 24 | (uint32_t)p[4 * i + 1] << 16 | (uint32_t)p[4 * i + 2] << 8 | p[4 * i + 3];
  for (int i = 16; i < 64; i++) {
    uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
    uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }
  uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
  for (int i = 0; i < 64; i++) {
    uint32_t t1 = hh + (rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25)) + ((e & f) ^ (~e & g)) + K256[i] + w[i];
    uint32_t t2 = (rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
    hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
  }
  h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

void Sha256::update(const uint8_t *p, size_t n)
{
  total += n;
  while (n > 0) {
    size_t k = std::min(n, sizeof buf - fill);
    memcpy(buf + fill, p, k);
    fill += k; p += k; n -= k;
    if (fill == sizeof buf) { block(buf); fill = 0; }
  }
}

void Sha256::final(uint8_t out[32])
{
  uint64_t bits = total * 8;
  uint8_t pad = 0x80;
  update(&pad, 1);
  pad = 0;
  while (fill != 56) update(&pad, 1);
  uint8_t len[8];
  for (int i = 0; i < 8; i++) len[i] = (uint8_t)(bits >> (56 - 8 * i));
  update(len, 8);
  for (int i = 0; i < 8; i++)
    for (int j = 0; j < 4; j++) out[4 * i + j] = (uint8_t)(h[i] >> (24 - 8 * j));
}

Hmac::Hmac(const uint8_t *key, size_t klen)
{
  uint8_t k[64] = {0}, pad[64];
  if (klen > 64) { Sha256 s; s.update(key, klen); s.final(k); }
  else if (klen > 0) memcpy(k, key, klen);
  for (int i = 0; i < 64; i++) pad[i] = k[i] ^ 0x36;
  inner.update(pad, 64);
  for (int i = 0; i < 64; i++) pad[i] = k[i] ^ 0x5c;
  outer.update(pad, 64);
  explicit_bzero(k, sizeof k);
  explicit_bzero(pad, sizeof pad);
}

// Hash states carry keyed HMAC pads and KDF intermediates.
Sha256::~Sha256()
{
  explicit_bzero(h, sizeof h);
  explicit_bzero(buf, sizeof buf);
}

void Hmac::mac(const uint8_t *msg, size_t n, uint8_t out[32]) const
{
  uint8_t d[32];
  Sha256 a = inner;
  a.update(msg, n);
  a.final(d);
  Sha256 b = outer;
  b.update(d, 32);
  b.final(out);
}
