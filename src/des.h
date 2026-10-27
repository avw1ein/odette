// SPDX-License-Identifier: MIT
// Copyright (c) 1993-1994, 2026 Andy van Wezel

#pragma once

#include <cstdint>

// Single-DES with one expanded key; the lookup tables are shared and built at startup.
class Des {
public:
  ~Des();
  void setkey(const uint8_t key[8]);
  void block(uint8_t *block, bool encrypt) const;

private:
  uint8_t kn_[16][8] = {};
};
