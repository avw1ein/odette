// SPDX-License-Identifier: MIT
// Copyright (c) 1993-1994, 2026 Andy van Wezel

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

typedef std::vector<uint8_t> Buf;

// Container: magic "OD" 5 2 | log2(N), r, p, 0 | salt | IV | ciphertext | HMAC-SHA-512 tag.
enum { SALT_LEN = 16, IV_LEN = 256, HDR_LEN = 4 + 4 + SALT_LEN + IV_LEN, TAG_LEN = 64, NL = 8 };
struct KdfParams { uint32_t logn, r, p; };
static const KdfParams DEFAULT_KDF = { 17, 8, 1 };  // 128 MiB of memory per guess
static const uint64_t MAX_KDF_BYTES = 1ull << 28;
static const char MAGIC[4] = { 'O', 'D', 5, 2 };

// Names the file or argument that the next errorexit message refers to.
extern std::string errarg;

[[noreturn]] void errorexit(int numer);

Buf readfile(const std::string &name);
void writefile(const std::string &name, const Buf &data);
// Exits with error 14 if the system random generator fails.
void randbytes(uint8_t *p, size_t n);
// Zeroises memory in a way the compiler will not remove.
void wipe(void *p, size_t n);
// Disables core dumps and ptrace by other processes of the same user.
void lockdown();
