// SPDX-License-Identifier: MIT
// Copyright (c) 1993-1994, 2026 Andy van Wezel

#include "keys.h"

#include <cstdio>
#include <cstring>
#include <termios.h>
#include <unistd.h>

#include "kdf.h"
#include "sha512.h"

namespace {

int htoa(char c)
{
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return 10 + c - 'a';
  if (c >= 'A' && c <= 'F') return 10 + c - 'A';
  return -1;
}

uint8_t length_mask(const uint8_t key[NL][8])
{
  uint8_t m = 0;
  for (int n = 0, k = 1; n < NL; n += 2, k += 2) {
    for (int i = 0; i < 8; i++) m ^= key[n][i] & 0x7F;
    for (int i = 0; i < 8; i++) m ^= (uint8_t)(key[k][i] << 1);
  }
  return m;
}

}  // namespace

KeyInput::~KeyInput()
{
  if (!phrase.empty()) wipe(&phrase[0], phrase.size());
  wipe(key, sizeof key);
}

KeyMaterial::~KeyMaterial()
{
  wipe(key, sizeof key);
  wipe(mackey, sizeof mackey);
}

void readkeyfile(const std::string &name, uint8_t key[NL][8])
{
  errarg = name;
  FILE *fh = fopen(name.c_str(), "r");
  if (!fh) errorexit(1);
  char line[256];
  std::string parse;
  for (int n = 0; n < NL; n++) {
    bool got = false;
    while (fgets(line, sizeof line, fh)) {
      const char *p = line;
      while (*p == ' ' || *p == '\t') p++;
      parse.clear();
      while (*p && *p != ' ' && *p != '\t' && *p != '\n') parse += *p++;
      if (!parse.empty() && parse[0] != ';') { got = true; break; }
    }
    errarg = name;  // never echo key material
    if (!got || parse.size() != 16) { fclose(fh); errorexit(5); }
    for (int i = 0; i < 16; i += 2) {
      int hi = htoa(parse[i]), lo = htoa(parse[i + 1]);
      if (hi < 0 || lo < 0) { fclose(fh); errorexit(5); }
      key[n][i / 2] = (uint8_t)((hi << 4) | lo);
    }
  }
  fclose(fh);
  wipe(line, sizeof line);
  wipe(&parse[0], parse.size());
}

namespace {

// Reads one line without echo on a terminal; false on EOF before any character.
bool read_hidden(const char *prompt, std::string &s, bool tty)
{
  fputs(prompt, stderr);
  fflush(stderr);
  termios old{};
  if (tty) {
    tcgetattr(STDIN_FILENO, &old);
    termios t = old;
    t.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &t);
  }
  s.clear();
  int c;
  while ((c = getchar()) != EOF && c != '\n') s += (char)c;
  if (tty) {
    tcsetattr(STDIN_FILENO, TCSANOW, &old);
    fputc('\n', stderr);
  }
  return !(c == EOF && s.empty());
}

}  // namespace

std::string getphrase(bool confirm)
{
  const size_t maxlen = 156;
  std::string s, again;
  bool tty = isatty(STDIN_FILENO);
  for (;;) {
    if (!read_hidden("Enter key phrase (minimum 48 characters): ", s, tty)) { errarg = "phrase"; errorexit(10); }
    size_t last = s.find_last_not_of(' ');
    if (last == std::string::npos || last < 47) {
      fputs("Phrase too short.\n", stderr);
      if (!tty) { errarg = "phrase"; errorexit(10); }
      continue;
    }
    if (confirm && tty) {
      if (!read_hidden("Repeat key phrase: ", again, tty)) { errarg = "phrase"; errorexit(10); }
      bool same = again == s;
      wipe(&again[0], again.size());
      if (!same) { fputs("Phrases differ.\n", stderr); continue; }
    }
    break;
  }
  if (s.size() > maxlen) {
    fprintf(stderr, "Warning: only the first %zu characters of the phrase are used.\n", maxlen);
    s.resize(maxlen);
  }
  s.resize(192, ' ');
  return s;
}

bool kdf_ok(const KdfParams &k)
{
  if (k.logn < 4 || k.logn > 20 || k.r < 1 || k.r > 16 || k.p < 1 || k.p > 4) return false;
  return ((uint64_t)128 * k.r << k.logn) <= MAX_KDF_BYTES;
}

KeyMaterial derive_keys(const KeyInput &in, const uint8_t *salt, const KdfParams &kdf)
{
  KeyMaterial km;
  if (in.usephrase) {
    Buf dk = scrypt(in.phrase, salt, SALT_LEN, 1u << kdf.logn, kdf.r, kdf.p, NL * 8 + sizeof km.mackey);
    memcpy(km.key, dk.data(), NL * 8);
    memcpy(km.mackey, dk.data() + NL * 8, sizeof km.mackey);
    wipe(dk.data(), dk.size());
  } else {
    memcpy(km.key, in.key, NL * 8);
    static const char label[] = "Odette 5.02 mac";
    Hmac512(&km.key[0][0], NL * 8).mac((const uint8_t *)label, sizeof label - 1, km.mackey);
  }
  km.lenmask = length_mask(km.key);
  return km;
}
