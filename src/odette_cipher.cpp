// SPDX-License-Identifier: MIT
// Copyright (c) 1993-1994, 2026 Andy van Wezel

#include "odette_cipher.h"

#include <cstring>

namespace {

void xor256(uint8_t *b, const uint8_t *w)
{
  for (int i = 0; i < 256; i++) b[i] ^= w[i];
}

void swap_nibbles(uint8_t *work, size_t bs)
{
  for (size_t i = 0, j = bs / 2; i < bs / 2; i++, j++) {
    uint8_t h1 = (work[i] & 0xF0) >> 4, l1 = work[i] & 0x0F;
    uint8_t h2 = work[j] & 0xF0, l2 = (work[j] & 0x0F) << 4;
    work[i] = l2 | l1;
    work[j] = h2 | h1;
  }
}

void swap_groups(uint8_t *blk, size_t bs)
{
  for (size_t off = 0; off < 256; off += bs) swap_nibbles(blk + off, bs);
}

const char WHITE_LABEL[] = "Odette 5.01 white";
const char TWEAK_LABEL[] = "Odette 5.01 tweak";

}  // namespace

OdetteCipher::OdetteCipher(const uint8_t key[NL][8], const uint8_t salt[SALT_LEN])
  : tweakmac_(&key[0][0], NL * 8)
{
  for (int i = 0; i < NL; i++) des_[i].setkey(key[i]);
  for (int j = 0; j <= NL; j++)
    for (int c = 0; c < 4; c++) {
      Buf msg(WHITE_LABEL, WHITE_LABEL + sizeof WHITE_LABEL - 1);
      msg.insert(msg.end(), salt, salt + SALT_LEN);
      msg.push_back((uint8_t)j);
      msg.push_back((uint8_t)c);
      tweakmac_.mac(msg.data(), msg.size(), &white_[j][64 * c]);
    }
  memcpy(salt_, salt, SALT_LEN);
}

void OdetteCipher::tweak(uint64_t index, uint8_t out[256]) const
{
  uint8_t msg[sizeof TWEAK_LABEL - 1 + SALT_LEN + 9];
  memcpy(msg, TWEAK_LABEL, sizeof TWEAK_LABEL - 1);
  memcpy(msg + sizeof TWEAK_LABEL - 1, salt_, SALT_LEN);
  for (int k = 0; k < 8; k++) msg[sizeof TWEAK_LABEL - 1 + SALT_LEN + k] = (uint8_t)(index >> (56 - 8 * k));
  for (int c = 0; c < 4; c++) {
    msg[sizeof msg - 1] = (uint8_t)c;
    tweakmac_.mac(msg, sizeof msg, out + 64 * c);
  }
}

// P256, then per layer: XOR, DES, and P16, P32, P64, P128, P256, P16, P32 between layers; final XOR.
void OdetteCipher::encrypt_block(uint8_t *b) const
{
  swap_nibbles(b, 256);
  for (int l = 0; l < NL; l++) {
    xor256(b, white_[l]);
    for (int i = 0; i < 256; i += 8) des_[l].block(b + i, true);
    if (l < NL - 1) swap_groups(b, (size_t)16 << (l % 5));
  }
  xor256(b, white_[NL]);
}

void OdetteCipher::decrypt_block(uint8_t *b) const
{
  xor256(b, white_[NL]);
  for (int l = NL - 1; l >= 0; l--) {
    for (int i = 0; i < 256; i += 8) des_[l].block(b + i, false);
    xor256(b, white_[l]);
    if (l > 0) swap_groups(b, (size_t)16 << ((l - 1) % 5));
    else swap_nibbles(b, 256);
  }
}

// CBC around all layers, with an XEX tweak per block: every block is its own permutation instance,
// and no single layer sees a known input difference.
Buf OdetteCipher::cbc_encrypt(const Buf &in, const uint8_t *iv) const
{
  Buf out(in.size());
  uint8_t prev[256], work[256], tw[256];
  memcpy(prev, iv, 256);
  for (size_t b = 0; b + 256 <= in.size(); b += 256) {
    tweak(b / 256, tw);
    for (int i = 0; i < 256; i++) work[i] = in[b + i] ^ prev[i] ^ tw[i];
    encrypt_block(work);
    for (int i = 0; i < 256; i++) work[i] ^= tw[i];
    memcpy(&out[b], work, 256);
    memcpy(prev, work, 256);
  }
  return out;
}

Buf OdetteCipher::cbc_decrypt(const Buf &in, const uint8_t *iv) const
{
  Buf out(in.size());
  uint8_t prev[256], work[256], tw[256];
  memcpy(prev, iv, 256);
  for (size_t b = 0; b + 256 <= in.size(); b += 256) {
    tweak(b / 256, tw);
    for (int i = 0; i < 256; i++) work[i] = in[b + i] ^ tw[i];
    decrypt_block(work);
    for (int i = 0; i < 256; i++) out[b + i] = work[i] ^ prev[i] ^ tw[i];
    memcpy(prev, &in[b], 256);
  }
  return out;
}

Buf pad256(const Buf &in, uint8_t lenmask)
{
  size_t cnt = in.size() % 256;
  Buf out(in);
  out.resize(in.size() - cnt + 256);
  if (cnt + 1 < 256) randbytes(&out[in.size()], 255 - cnt);
  out[out.size() - 1] = (uint8_t)(cnt ^ lenmask);
  return out;
}

Buf unpad256(const Buf &in, uint8_t lenmask)
{
  size_t cnt = (uint8_t)(in[in.size() - 1] ^ lenmask);
  if (cnt > 255) cnt = 255;
  return Buf(in.begin(), in.end() - 256 + cnt);
}
