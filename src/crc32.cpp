// SPDX-License-Identifier: MIT
// Copyright (c) 1993-1994, 2026 Andy van Wezel

#include "crc32.h"

namespace {

struct Table {
  uint32_t t[256];
  Table()
  {
    for (uint32_t i = 0; i < 256; i++) {
      uint32_t c = i;
      for (int k = 0; k < 8; k++) c = (c & 1) ? (c >> 1) ^ 0xedb88320u : c >> 1;
      t[i] = c;
    }
  }
};

const Table table;

}  // namespace

void Crc32::update(uint8_t b)
{
  reg_ = (reg_ >> 8) ^ table.t[(reg_ ^ b) & 0xff];
}
