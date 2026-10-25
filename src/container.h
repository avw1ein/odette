// SPDX-License-Identifier: MIT
// Copyright (c) 1993-1994, 2026 Andy van Wezel

#pragma once

#include "common.h"
#include "keys.h"

// Pads, encrypts and authenticates `plain` into a complete container.
Buf seal(const Buf &plain, const KeyInput &keys, const KdfParams &kdf);

// Verifies and decrypts a container; exits with error 13 on any mismatch.
Buf unseal(const Buf &blob, const KeyInput &keys);
