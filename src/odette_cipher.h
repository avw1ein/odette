// SPDX-License-Identifier: MIT
// Copyright (c) 1993-1994, 2026 Andy van Wezel

#pragma once

#include "common.h"
#include "des.h"
#include "sha512.h"

// The 2048-bit wide-block cipher: eight DES layers with per-layer whitening and nibble permutations,
// wrapped in CBC with a per-block XEX tweak. Whitening and tweak depend on every key bit and the salt.
class OdetteCipher {
public:
  OdetteCipher(const uint8_t key[NL][8], const uint8_t salt[SALT_LEN]);

  void encrypt_block(uint8_t *b) const;
  void decrypt_block(uint8_t *b) const;

  // Per-block 2048-bit XEX mask: a PRF of the key, the salt and the block index.
  void tweak(uint64_t index, uint8_t out[256]) const;

  // Input length must be a multiple of 256.
  Buf cbc_encrypt(const Buf &in, const uint8_t *iv) const;
  Buf cbc_decrypt(const Buf &in, const uint8_t *iv) const;

private:
  Des des_[NL];
  uint8_t white_[NL + 1][256];
  Hmac512 tweakmac_;  // keyed once; pad states are reused for every block
  uint8_t salt_[SALT_LEN];
};

// Random fill plus a masked length byte, always at least one byte of padding.
Buf pad256(const Buf &in, uint8_t lenmask);
Buf unpad256(const Buf &in, uint8_t lenmask);
