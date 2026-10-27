// SPDX-License-Identifier: MIT
// Copyright (c) 1993-1994, 2026 Andy van Wezel

#include "kdf.h"

#include <cstring>
#include <new>

#include "sha256.h"

Buf pbkdf2(const std::string &pw, const uint8_t *salt, size_t slen, uint32_t iters, size_t outlen)
{
  Hmac h((const uint8_t *)pw.data(), pw.size());
  Buf out;
  for (uint32_t blk = 1; out.size() < outlen; blk++) {
    Buf s(salt, salt + slen);
    for (int i = 3; i >= 0; i--) s.push_back((uint8_t)(blk >> (8 * i)));
    uint8_t u[32], t[32];
    h.mac(s.data(), s.size(), u);
    memcpy(t, u, 32);
    for (uint32_t i = 1; i < iters; i++) {
      h.mac(u, 32, u);
      for (int j = 0; j < 32; j++) t[j] ^= u[j];
    }
    out.insert(out.end(), t, t + 32);
    wipe(u, sizeof u);
    wipe(t, sizeof t);
  }
  out.resize(outlen);
  return out;
}

namespace {

void salsa20_8(uint32_t B[16])
{
  uint32_t x[16];
  memcpy(x, B, 64);
  auto R = [](uint32_t a, int b) { return (a << b) | (a >> (32 - b)); };
  for (int i = 0; i < 8; i += 2) {
    x[ 4] ^= R(x[ 0] + x[12],  7);  x[ 8] ^= R(x[ 4] + x[ 0],  9);
    x[12] ^= R(x[ 8] + x[ 4], 13);  x[ 0] ^= R(x[12] + x[ 8], 18);
    x[ 9] ^= R(x[ 5] + x[ 1],  7);  x[13] ^= R(x[ 9] + x[ 5],  9);
    x[ 1] ^= R(x[13] + x[ 9], 13);  x[ 5] ^= R(x[ 1] + x[13], 18);
    x[14] ^= R(x[10] + x[ 6],  7);  x[ 2] ^= R(x[14] + x[10],  9);
    x[ 6] ^= R(x[ 2] + x[14], 13);  x[10] ^= R(x[ 6] + x[ 2], 18);
    x[ 3] ^= R(x[15] + x[11],  7);  x[ 7] ^= R(x[ 3] + x[15],  9);
    x[11] ^= R(x[ 7] + x[ 3], 13);  x[15] ^= R(x[11] + x[ 7], 18);
    x[ 1] ^= R(x[ 0] + x[ 3],  7);  x[ 2] ^= R(x[ 1] + x[ 0],  9);
    x[ 3] ^= R(x[ 2] + x[ 1], 13);  x[ 0] ^= R(x[ 3] + x[ 2], 18);
    x[ 6] ^= R(x[ 5] + x[ 4],  7);  x[ 7] ^= R(x[ 6] + x[ 5],  9);
    x[ 4] ^= R(x[ 7] + x[ 6], 13);  x[ 5] ^= R(x[ 4] + x[ 7], 18);
    x[11] ^= R(x[10] + x[ 9],  7);  x[ 8] ^= R(x[11] + x[10],  9);
    x[ 9] ^= R(x[ 8] + x[11], 13);  x[10] ^= R(x[ 9] + x[ 8], 18);
    x[12] ^= R(x[15] + x[14],  7);  x[13] ^= R(x[12] + x[15],  9);
    x[14] ^= R(x[13] + x[12], 13);  x[15] ^= R(x[14] + x[13], 18);
  }
  for (int i = 0; i < 16; i++) B[i] += x[i];
}

void scrypt_blockmix(uint32_t *B, uint32_t *tmp, size_t r)
{
  uint32_t X[16];
  memcpy(X, &B[(2 * r - 1) * 16], 64);
  for (size_t i = 0; i < 2 * r; i++) {
    for (int k = 0; k < 16; k++) X[k] ^= B[i * 16 + k];
    salsa20_8(X);
    memcpy(&tmp[((i & 1) ? r + i / 2 : i / 2) * 16], X, 64);
  }
  memcpy(B, tmp, 128 * r);
}

void scrypt_romix(uint8_t *blk, size_t r, uint32_t N)
{
  const size_t w = 32 * r;
  std::vector<uint32_t> X(w), T(w), V;
  try { V.resize((size_t)N * w); } catch (const std::bad_alloc &) { errorexit(7); }
  for (size_t i = 0; i < w; i++)
    X[i] = (uint32_t)blk[4 * i] | (uint32_t)blk[4 * i + 1] << 8 | (uint32_t)blk[4 * i + 2] << 16 | (uint32_t)blk[4 * i + 3] << 24;
  for (uint32_t i = 0; i < N; i++) {
    memcpy(&V[(size_t)i * w], X.data(), 4 * w);
    scrypt_blockmix(X.data(), T.data(), r);
  }
  for (uint32_t i = 0; i < N; i++) {
    const uint32_t j = X[(2 * r - 1) * 16] & (N - 1);
    for (size_t k = 0; k < w; k++) X[k] ^= V[(size_t)j * w + k];
    scrypt_blockmix(X.data(), T.data(), r);
  }
  for (size_t i = 0; i < w; i++)
    for (int j = 0; j < 4; j++) blk[4 * i + j] = (uint8_t)(X[i] >> (8 * j));
  wipe(X.data(), 4 * w);
  wipe(T.data(), 4 * w);
  wipe(V.data(), 4 * V.size());
}

}  // namespace

Buf scrypt(const std::string &pw, const uint8_t *salt, size_t slen, uint32_t N, uint32_t r, uint32_t p, size_t outlen)
{
  Buf B = pbkdf2(pw, salt, slen, 1, (size_t)128 * r * p);
  for (uint32_t i = 0; i < p; i++) scrypt_romix(&B[(size_t)i * 128 * r], r, N);
  Buf out = pbkdf2(pw, B.data(), B.size(), 1, outlen);
  wipe(B.data(), B.size());
  return out;
}
