// SPDX-License-Identifier: MIT
// Copyright (c) 1993-1994, 2026 Andy van Wezel

#pragma once

#include "common.h"

Buf pbkdf2(const std::string &pw, const uint8_t *salt, size_t slen, uint32_t iters, size_t outlen);

// RFC 7914; N must be a power of two.
Buf scrypt(const std::string &pw, const uint8_t *salt, size_t slen, uint32_t N, uint32_t r, uint32_t p, size_t outlen);
