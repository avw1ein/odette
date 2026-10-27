// SPDX-License-Identifier: MIT
// Copyright (c) 1993-1994, 2026 Andy van Wezel

#include "container.h"

#include <cstring>

#include "odette_cipher.h"
#include "sha512.h"

namespace {

bool all_zero(const uint8_t *p, size_t n)
{
  uint8_t acc = 0;
  for (size_t i = 0; i < n; i++) acc |= p[i];
  return acc == 0;
}

}  // namespace

// Salt and IV are always drawn here; no caller can supply them. A fixed salt or IV would let two
// files share a permutation instance, which is the one thing the analysis requires never happens.
Buf seal(const Buf &plain, const KeyInput &keys, const KdfParams &kdf)
{
  uint8_t iv[IV_LEN], salt[SALT_LEN];
  randbytes(salt, SALT_LEN);
  randbytes(iv, IV_LEN);
  if (all_zero(salt, SALT_LEN) || all_zero(iv, IV_LEN)) errorexit(14);
  KeyMaterial km = derive_keys(keys, salt, kdf);
  OdetteCipher cipher(km.key, salt);

  Buf ct = cipher.cbc_encrypt(pad256(plain, km.lenmask), iv);

  Buf out(MAGIC, MAGIC + 4);
  out.push_back((uint8_t)kdf.logn);
  out.push_back((uint8_t)kdf.r);
  out.push_back((uint8_t)kdf.p);
  out.push_back(0);
  out.insert(out.end(), salt, salt + SALT_LEN);
  out.insert(out.end(), iv, iv + IV_LEN);
  out.insert(out.end(), ct.begin(), ct.end());
  uint8_t tag[TAG_LEN];
  Hmac512(km.mackey, sizeof km.mackey).mac(out.data(), out.size(), tag);
  out.insert(out.end(), tag, tag + TAG_LEN);
  return out;
}

Buf unseal(const Buf &d, const KeyInput &keys)
{
  size_t body = d.size() >= HDR_LEN + TAG_LEN ? d.size() - HDR_LEN - TAG_LEN : 0;
  if (body < 256 || body % 256 != 0 || memcmp(d.data(), MAGIC, 4) != 0) errorexit(13);
  KdfParams kdf = { d[4], d[5], d[6] };
  if (d[7] != 0 || !kdf_ok(kdf)) errorexit(13);
  uint8_t iv[IV_LEN], salt[SALT_LEN];
  memcpy(salt, &d[8], SALT_LEN);
  memcpy(iv, &d[8 + SALT_LEN], IV_LEN);
  KeyMaterial km = derive_keys(keys, salt, kdf);

  uint8_t tag[TAG_LEN], diff = 0;
  Hmac512(km.mackey, sizeof km.mackey).mac(d.data(), d.size() - TAG_LEN, tag);
  for (int i = 0; i < TAG_LEN; i++) diff |= tag[i] ^ d[d.size() - TAG_LEN + i];
  if (diff) errorexit(13);

  Buf ct(d.begin() + HDR_LEN, d.end() - TAG_LEN);
  OdetteCipher cipher(km.key, salt);
  return unpad256(cipher.cbc_decrypt(ct, iv), km.lenmask);
}
