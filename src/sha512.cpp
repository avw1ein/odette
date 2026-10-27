// SPDX-License-Identifier: MIT
// Copyright (c) 1993-1994, 2026 Andy van Wezel

#include "sha512.h"

#include <algorithm>
#include <cstring>

namespace {

const uint64_t K512[80] = {
  0x428a2f98d728ae22ull, 0x7137449123ef65cdull, 0xb5c0fbcfec4d3b2full, 0xe9b5dba58189dbbcull,
  0x3956c25bf348b538ull, 0x59f111f1b605d019ull, 0x923f82a4af194f9bull, 0xab1c5ed5da6d8118ull,
  0xd807aa98a3030242ull, 0x12835b0145706fbeull, 0x243185be4ee4b28cull, 0x550c7dc3d5ffb4e2ull,
  0x72be5d74f27b896full, 0x80deb1fe3b1696b1ull, 0x9bdc06a725c71235ull, 0xc19bf174cf692694ull,
  0xe49b69c19ef14ad2ull, 0xefbe4786384f25e3ull, 0x0fc19dc68b8cd5b5ull, 0x240ca1cc77ac9c65ull,
  0x2de92c6f592b0275ull, 0x4a7484aa6ea6e483ull, 0x5cb0a9dcbd41fbd4ull, 0x76f988da831153b5ull,
  0x983e5152ee66dfabull, 0xa831c66d2db43210ull, 0xb00327c898fb213full, 0xbf597fc7beef0ee4ull,
  0xc6e00bf33da88fc2ull, 0xd5a79147930aa725ull, 0x06ca6351e003826full, 0x142929670a0e6e70ull,
  0x27b70a8546d22ffcull, 0x2e1b21385c26c926ull, 0x4d2c6dfc5ac42aedull, 0x53380d139d95b3dfull,
  0x650a73548baf63deull, 0x766a0abb3c77b2a8ull, 0x81c2c92e47edaee6ull, 0x92722c851482353bull,
  0xa2bfe8a14cf10364ull, 0xa81a664bbc423001ull, 0xc24b8b70d0f89791ull, 0xc76c51a30654be30ull,
  0xd192e819d6ef5218ull, 0xd69906245565a910ull, 0xf40e35855771202aull, 0x106aa07032bbd1b8ull,
  0x19a4c116b8d2d0c8ull, 0x1e376c085141ab53ull, 0x2748774cdf8eeb99ull, 0x34b0bcb5e19b48a8ull,
  0x391c0cb3c5c95a63ull, 0x4ed8aa4ae3418acbull, 0x5b9cca4f7763e373ull, 0x682e6ff3d6b2b8a3ull,
  0x748f82ee5defb2fcull, 0x78a5636f43172f60ull, 0x84c87814a1f0ab72ull, 0x8cc702081a6439ecull,
  0x90befffa23631e28ull, 0xa4506cebde82bde9ull, 0xbef9a3f7b2c67915ull, 0xc67178f2e372532bull,
  0xca273eceea26619cull, 0xd186b8c721c0c207ull, 0xeada7dd6cde0eb1eull, 0xf57d4f7fee6ed178ull,
  0x06f067aa72176fbaull, 0x0a637dc5a2c898a6ull, 0x113f9804bef90daeull, 0x1b710b35131c471bull,
  0x28db77f523047d84ull, 0x32caab7b40c72493ull, 0x3c9ebe0a15c9bebcull, 0x431d67c49c100d4cull,
  0x4cc5d4becb3e42b6ull, 0x597f299cfc657e2aull, 0x5fcb6fab3ad6faecull, 0x6c44198c4a475817ull
};

inline uint64_t rotr64(uint64_t x, int n) { return (x >> n) | (x << (64 - n)); }

}  // namespace

void Sha512::block(const uint8_t *p)
{
  uint64_t w[80];
  for (int i = 0; i < 16; i++) {
    w[i] = 0;
    for (int j = 0; j < 8; j++) w[i] = w[i] << 8 | p[8 * i + j];
  }
  for (int i = 16; i < 80; i++) {
    uint64_t s0 = rotr64(w[i - 15], 1) ^ rotr64(w[i - 15], 8) ^ (w[i - 15] >> 7);
    uint64_t s1 = rotr64(w[i - 2], 19) ^ rotr64(w[i - 2], 61) ^ (w[i - 2] >> 6);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }
  uint64_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
  for (int i = 0; i < 80; i++) {
    uint64_t t1 = hh + (rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41)) + ((e & f) ^ (~e & g)) + K512[i] + w[i];
    uint64_t t2 = (rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39)) + ((a & b) ^ (a & c) ^ (b & c));
    hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
  }
  h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

void Sha512::update(const uint8_t *p, size_t n)
{
  total += n;
  while (n > 0) {
    size_t k = std::min(n, sizeof buf - fill);
    memcpy(buf + fill, p, k);
    fill += k; p += k; n -= k;
    if (fill == sizeof buf) { block(buf); fill = 0; }
  }
}

void Sha512::final(uint8_t out[64])
{
  uint64_t bits = total * 8;
  uint8_t pad = 0x80;
  update(&pad, 1);
  pad = 0;
  while (fill != 112) update(&pad, 1);
  uint8_t len[16] = {0};
  for (int i = 0; i < 8; i++) len[8 + i] = (uint8_t)(bits >> (56 - 8 * i));
  update(len, 16);
  for (int i = 0; i < 8; i++)
    for (int j = 0; j < 8; j++) out[8 * i + j] = (uint8_t)(h[i] >> (56 - 8 * j));
}

Hmac512::Hmac512(const uint8_t *key, size_t klen)
{
  uint8_t k[128] = {0}, pad[128];
  if (klen > 128) { Sha512 s; s.update(key, klen); s.final(k); }
  else if (klen > 0) memcpy(k, key, klen);
  for (int i = 0; i < 128; i++) pad[i] = k[i] ^ 0x36;
  inner.update(pad, 128);
  for (int i = 0; i < 128; i++) pad[i] = k[i] ^ 0x5c;
  outer.update(pad, 128);
  explicit_bzero(k, sizeof k);
  explicit_bzero(pad, sizeof pad);
}

// Hash states carry keyed HMAC pads and whitening or tweak material.
Sha512::~Sha512()
{
  explicit_bzero(h, sizeof h);
  explicit_bzero(buf, sizeof buf);
}

void Hmac512::mac(const uint8_t *msg, size_t n, uint8_t out[64]) const
{
  uint8_t d[64];
  Sha512 a = inner;
  a.update(msg, n);
  a.final(d);
  Sha512 b = outer;
  b.update(d, 64);
  b.final(out);
}
