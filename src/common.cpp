// SPDX-License-Identifier: MIT
// Copyright (c) 1993-1994, 2026 Andy van Wezel

#include "common.h"

#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <sys/random.h>
#include <unistd.h>

std::string errarg;

[[noreturn]] void errorexit(int numer)
{
  const char *a = errarg.c_str();
  switch (numer) {
    case 1:  fprintf(stderr, "ERROR#1: Can't read from: %s\n", a); break;
    case 2:  fprintf(stderr, "ERROR#2: Can't write to: %s\n", a); break;
    case 3:  fputs("ERROR#3: Wrong number of parameters.\nType odette for help.\n", stderr); break;
    case 4:  fprintf(stderr, "ERROR#4: Invalid option: %s\nType odette for help.\n", a); break;
    case 5:  fprintf(stderr, "ERROR#5: Faulty keyfile: %s\n", a); break;
    case 6:  fputs("ERROR#6: Inputfile and outputfile must differ.\nType odette for help.\n", stderr); break;
    case 7:  fputs("ERROR#7: Not enough memory.\n", stderr); break;
    case 8:  fprintf(stderr, "ERROR#8: Can't find begin of code in: %s\n", a); break;
    case 9:  fprintf(stderr, "ERROR#9: Duplicate argument on commandline: %s\nType odette for help.\n", a); break;
    case 10: fprintf(stderr, "ERROR#10: Argument missing: %s\nType odette for help.\n", a); break;
    case 11: fprintf(stderr, "ERROR#11: Can't find end of code in: %s\n", a); break;
    case 12: fprintf(stderr, "ERROR#12: CRC error in: %s\n", a); break;
    case 13: fputs("ERROR#13: Authentication failed (wrong key, or data damaged or not Odette 5.01).\n", stderr); break;
    default: break;
  }
  exit(numer);
}

Buf readfile(const std::string &name)
{
  errarg = name;
  FILE *fh = fopen(name.c_str(), "rb");
  if (!fh) errorexit(1);
  Buf data;
  uint8_t chunk[65536];
  size_t n;
  while ((n = fread(chunk, 1, sizeof chunk, fh)) > 0) data.insert(data.end(), chunk, chunk + n);
  bool bad = ferror(fh) != 0;
  fclose(fh);
  if (bad) errorexit(1);
  return data;
}

void writefile(const std::string &name, const Buf &data)
{
  errarg = name;
  int fd = open(name.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
  if (fd < 0) errorexit(2);
  FILE *fh = fdopen(fd, "wb");
  if (!fh) { close(fd); errorexit(2); }
  if (!data.empty() && fwrite(data.data(), 1, data.size(), fh) != data.size()) { fclose(fh); errorexit(2); }
  if (fclose(fh) != 0) errorexit(2);
}

void randbytes(uint8_t *p, size_t n)
{
  if (getrandom(p, n, 0) != (ssize_t)n) errorexit(7);
}
