// SPDX-License-Identifier: MIT
// Copyright (c) 1993-1994, 2026 Andy van Wezel
//
// Odette 5.01 - Linux command line port of the DOS program by Andy van Wezel (1993 - 1994),
// ported and updated 2026.
//
// Build: make
//
// The file format differs from the MS DOS original and is not compatible with it.

#include <cctype>
#include <cstdio>
#include <new>
#include <string>
#include <sys/stat.h>

#include "armor.h"
#include "common.h"
#include "container.h"
#include "keys.h"

namespace {

struct Args {
  bool encrypt = true;
  bool binary = true;  // false: e-mail (armored) text
  bool usephrase = false;
  std::string in, out, keyfile;
};

void usage()
{
  puts("Odette 5.01 Copyright (C) by Andy van Wezel 1993 - 1994, 2026\n");
  puts("Usage: odette act=e|d|em|dm in=infile out=outfile phrase|key=keyfile");
  puts(" e            Encryption.");
  puts(" d            Decryption.");
  puts(" em           Encryption to e-mail message.");
  puts(" dm           Decryption from e-mail message.");
  puts(" infile       Data to be en/decrypted.");
  puts(" outfile      Result of en/decryption.");
  puts(" keyfile      Contains the eight keys.");
  puts(" phrase       Prompt for a phrase (min. 48 characters). Don't use a keyfile.\n");
  puts("*Odette performs a DES8 encryption with 2048-bit whitening on textfiles or");
  puts(" executables. The block size grows to 2048 bits. Eight 64-bit keys feed");
  puts(" every layer. Output is authenticated (HMAC-SHA-512).");
  puts("*Odette is free software released under the MIT License (see the LICENSE file),");
  puts(" and provided as is. Andy van Wezel makes no claims and offers no warranties");
  puts(" of any sort with Odette.");
}

Args parse_args(int argc, char *argv[])
{
  Args a;
  int bewerking = -1;  // 1 = encrypt, 2 = decrypt, 0 = invalid

  if (argc != 5) errorexit(3);

  for (int i = 1; i <= 4; i++) {
    std::string arg = argv[i];
    size_t eq = arg.find('=');
    std::string name = arg.substr(0, eq == std::string::npos ? arg.size() : eq + 1);
    std::string val = eq == std::string::npos ? "" : arg.substr(eq + 1);
    for (char &c : name) c = (char)tolower((unsigned char)c);

    if (name == "act=") {
      if (bewerking != -1) { errarg = "act="; errorexit(9); }
      for (char &c : val) c = (char)tolower((unsigned char)c);
      bewerking = 0;
      if (val == "e")  { bewerking = 1; a.binary = true; }
      if (val == "d")  { bewerking = 2; a.binary = true; }
      if (val == "em") { bewerking = 1; a.binary = false; }
      if (val == "dm") { bewerking = 2; a.binary = false; }
    } else if (name == "in=") {
      if (!a.in.empty()) { errarg = "in="; errorexit(9); }
      a.in = val;
    } else if (name == "out=") {
      if (!a.out.empty()) { errarg = "out="; errorexit(9); }
      a.out = val;
    } else if (name == "key=") {
      if (!a.keyfile.empty()) { errarg = "key="; errorexit(9); }
      a.keyfile = val;
    } else if (name == "phrase") {
      if (a.usephrase) { errarg = "phrase"; errorexit(9); }
      a.usephrase = true;
    } else {
      errarg = arg;
      errorexit(4);
    }
  }

  if (bewerking == -1) { errarg = "act="; errorexit(10); }
  if (bewerking == 0)  { errarg = "act="; errorexit(4); }
  if (a.in.empty())    { errarg = "in="; errorexit(10); }
  if (a.out.empty())   { errarg = "out="; errorexit(10); }
  if (a.keyfile.empty() && !a.usephrase) { errarg = "phrase;key="; errorexit(10); }
  a.encrypt = bewerking == 1;
  return a;
}

}  // namespace

int main(int argc, char *argv[])
{
  if (argc == 1) { usage(); return 3; }
  Args args = parse_args(argc, argv);

  KeyInput keys;
  keys.usephrase = args.usephrase;
  if (args.usephrase) keys.phrase = getphrase(args.encrypt);

  struct stat s1, s2;
  if (args.in == args.out || (stat(args.in.c_str(), &s1) == 0 && stat(args.out.c_str(), &s2) == 0 &&
                              s1.st_dev == s2.st_dev && s1.st_ino == s2.st_ino))
    errorexit(6);

  if (!args.keyfile.empty()) readkeyfile(args.keyfile, keys.key);

  try {
    Buf d = readfile(args.in);
    if (args.encrypt) {
      d = seal(d, keys, DEFAULT_KDF);
      if (!args.binary) d = high2low(d);
    } else {
      if (!args.binary) d = low2high(d, args.in);
      d = unseal(d, keys);
    }
    writefile(args.out, d);
  } catch (const std::bad_alloc &) {
    errorexit(7);
  }
  return 0;
}
