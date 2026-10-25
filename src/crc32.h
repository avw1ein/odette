// SPDX-License-Identifier: MIT
// Copyright (c) 1993-1994, 2026 Andy van Wezel

#pragma once

#include <cstdint>

// CRC-32 (reflected, polynomial 0xEDB88320) without the final inversion, as the armor format expects.
class Crc32 {
public:
  void update(uint8_t b);
  uint32_t value() const { return reg_; }

private:
  uint32_t reg_ = 0xFFFFFFFFu;
};
