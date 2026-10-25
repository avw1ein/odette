// SPDX-License-Identifier: MIT
// Copyright (c) 1993-1994, 2026 Andy van Wezel

#pragma once

#include "common.h"

// Binary to "e-mail" text: base-64-like body between BEGIN/END lines, protected by a CRC-32.
Buf high2low(const Buf &in);

// Inverse of high2low; `name` is only used in error messages.
Buf low2high(const Buf &in, const std::string &name);
