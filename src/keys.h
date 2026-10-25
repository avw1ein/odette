// SPDX-License-Identifier: MIT
// Copyright (c) 1993-1994, 2026 Andy van Wezel

#pragma once

#include "common.h"

// Where the keys come from: eight 64-bit keys from a key file, or a phrase run through scrypt.
struct KeyInput {
  bool usephrase = false;
  std::string phrase;
  uint8_t key[NL][8] = {};  // only meaningful when !usephrase
};

// Everything the cipher and the container need once the salt is known.
struct KeyMaterial {
  uint8_t key[NL][8];
  uint8_t mackey[64];
  uint8_t lenmask;  // masks the length byte in the padding
};

void readkeyfile(const std::string &name, uint8_t key[NL][8]);

// Reads a phrase (no echo on a terminal); asks twice on a terminal when confirm is set.
// Result is padded with spaces to 192 bytes.
std::string getphrase(bool confirm);

bool kdf_ok(const KdfParams &k);

KeyMaterial derive_keys(const KeyInput &in, const uint8_t *salt, const KdfParams &kdf);
