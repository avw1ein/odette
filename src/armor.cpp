// SPDX-License-Identifier: MIT
// Copyright (c) 1993-1994, 2026 Andy van Wezel

#include "armor.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "crc32.h"

namespace {

const char *BEGIN_TAG = "*BEGIN Odette 5.01 message, valid char:";
const char *END_TAG = "*END Odette 5.01 message, CRC:";

}  // namespace

Buf high2low(const Buf &in)
{
  char tabel[64];
  for (int i = 0; i < 12; i++) tabel[i] = '0' + i;
  for (int i = 0; i < 26; i++) tabel[12 + i] = 'A' + i;
  for (int i = 0; i < 26; i++) tabel[38 + i] = 'a' + i;

  // The EOF marker (0xFF) is encoded as a final byte; low2high strips it.
  Buf data(in);
  data.push_back(0xFF);

  Crc32 crc;
  std::string o;
  char hdr[128];
  unsigned long fl = ((data.size()) * 4 + 2) / 3;
  snprintf(hdr, sizeof hdr, "\n%s %lu\n\n", BEGIN_TAG, fl);
  o += hdr;

  int wvdd = 0, posi = 0;
  uint8_t chb = 0, chc = 0;
  for (uint8_t cha : data) {
    crc.update(cha);
    switch (wvdd++) {
      case 0: chb = cha & 0x3; o += tabel[cha >> 2]; break;
      case 1: chc = cha & 0xF; o += tabel[(cha >> 4) | (chb << 4)]; break;
      case 2: o += tabel[((cha & 0xC0) >> 6) | (chc << 2)]; o += tabel[cha & 0x3F]; wvdd = 0; break;
    }
    if (posi++ >= 44) { posi = 0; o += '\n'; }
  }
  if (wvdd == 1) o += tabel[(chb << 4) & 0xFF];
  else if (wvdd == 2) o += tabel[(chc << 2) & 0xFF];

  snprintf(hdr, sizeof hdr, "\n\n%s %d\n\n", END_TAG, (int32_t)crc.value());
  o += hdr;
  return Buf(o.begin(), o.end());
}

Buf low2high(const Buf &in, const std::string &name)
{
  uint8_t tabel[256];
  memset(tabel, 255, sizeof tabel);
  for (int i = 0; i < 12; i++) tabel['0' + i] = i;
  for (int i = 0; i < 26; i++) tabel['A' + i] = 12 + i;
  for (int i = 0; i < 26; i++) tabel['a' + i] = 38 + i;

  const std::string text(in.begin(), in.end());
  errarg = name;

  size_t pos = 0;
  bool found = false;
  while (pos < text.size()) {
    if (!text.compare(pos, strlen(BEGIN_TAG), BEGIN_TAG)) { found = true; break; }
    size_t nl = text.find('\n', pos);
    if (nl == std::string::npos) break;
    pos = nl + 1;
  }
  if (!found) errorexit(8);
  unsigned long valchr = strtoul(text.c_str() + pos + strlen(BEGIN_TAG), nullptr, 10);
  size_t nl = text.find('\n', pos);
  pos = (nl == std::string::npos) ? text.size() : nl + 1;

  Crc32 crc;
  Buf out;
  unsigned long fl = 0;
  int wvdd = 0;
  uint8_t chb = 0, chc = 0;
  while (fl < valchr) {
    if (pos >= text.size()) errorexit(11);
    uint8_t cha = tabel[(uint8_t)text[pos++]];
    if (cha == 255) continue;
    fl++;
    switch (wvdd++) {
      case 0: chb = cha << 2; break;
      case 1: chc = cha & 0xF; cha = (cha >> 4) | chb; crc.update(cha); out.push_back(cha); break;
      case 2: chb = cha & 0x3; cha = (cha >> 2) | (chc << 4); crc.update(cha); out.push_back(cha); break;
      case 3: cha |= (chb << 6); crc.update(cha); out.push_back(cha); wvdd = 0; break;
    }
  }

  found = false;
  while (pos < text.size()) {
    if (!text.compare(pos, strlen(END_TAG), END_TAG)) { found = true; break; }
    size_t e = text.find('\n', pos);
    if (e == std::string::npos) break;
    pos = e + 1;
  }
  if (!found) errorexit(11);
  if ((int32_t)strtol(text.c_str() + pos + strlen(END_TAG), nullptr, 10) != (int32_t)crc.value()) errorexit(12);
  if (!out.empty()) out.pop_back();  // EOF marker added by high2low
  return out;
}
