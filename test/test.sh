#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (c) 1993-1994, 2026 Andy van Wezel
#
# Self-test for the Linux port. Run after `make`; works from any directory.
set -e
cd "$(dirname "$0")/.."
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT

./odette act=dm in=hello.ode out="$T/hello.txt" key=sample.key
grep -q "^Hello," "$T/hello.txt"
echo "ok: hello.ode decrypts"

for size in 0 1 255 256 257 1000 5000; do
  head -c "$size" /dev/urandom > "$T/in.bin"
  ./odette act=e  in="$T/in.bin" out="$T/e.bin"  key=sample.key
  ./odette act=d  in="$T/e.bin"  out="$T/d.bin"  key=sample.key
  cmp "$T/in.bin" "$T/d.bin"
  ./odette act=em in="$T/in.bin" out="$T/e.txt"  key=sample.key
  ./odette act=dm in="$T/e.txt"  out="$T/d2.bin" key=sample.key
  cmp "$T/in.bin" "$T/d2.bin"
done
echo "ok: round trips (binary and e-mail style)"

head -c 1 /dev/urandom > "$T/in.bin"
./odette act=e in="$T/in.bin" out="$T/e.bin" key=sample.key
[ "$(stat -c %s "$T/e.bin")" -eq $((280 + 256 + 64)) ] || { echo "FAIL: unexpected container size"; exit 1; }
echo "ok: container is header + one block + 64-byte tag"

P="The quick brown fox jumps over the lazy dog, again and again."
echo "$P" | ./odette act=em in=hello.ode out="$T/p.txt" phrase 2>/dev/null
echo "$P" | ./odette act=dm in="$T/p.txt" out="$T/p.out" phrase 2>/dev/null
echo "ok: phrase round trip"

cmp -s hello.ode "$T/p.out" || { echo "FAIL: phrase round trip mismatch"; exit 1; }
printf '%s\n' 0123456789abcdef fedcba9876543210 13579bdf02468ace a1b2c3d4e5f60718 \
  0f1e2d3c4b5a6978 1122334455667788 99aabbccddeeff00 0011223344556677 > "$T/otherkey"
rc=0; ./odette act=dm in="$T/p.txt" out="$T/bad" key="$T/otherkey" 2>/dev/null || rc=$?
[ "$rc" -eq 13 ] || { echo "FAIL: wrong key accepted"; exit 1; }
echo "ok: wrong key fails authentication"

sed 's/^BA7CDE4350091ADE/BA7CDE4350091ADF/' sample.key > "$T/paritykey"
if cmp -s sample.key "$T/paritykey"; then echo "FAIL: parity key not built"; exit 1; fi
rc=0; ./odette act=dm in=hello.ode out="$T/bad" key="$T/paritykey" 2>/dev/null || rc=$?
[ "$rc" -eq 13 ] || { echo "FAIL: key differing in a parity bit accepted"; exit 1; }
echo "ok: every key bit matters"

grep -E '^[0-9A-F]{16}' sample.key | head -n 6 > "$T/sixkeys"
rc=0; ./odette act=dm in=hello.ode out="$T/bad" key="$T/sixkeys" 2>/dev/null || rc=$?
[ "$rc" -eq 5 ] || { echo "FAIL: key file with too few keys accepted"; exit 1; }
echo "ok: key file needs eight keys"

sed 's/^\(.\{20\}\)./\1A/' "$T/p.txt" > "$T/corrupt.txt"
if ./odette act=dm in="$T/corrupt.txt" out="$T/bad2" key=sample.key 2>/dev/null; then
  echo "FAIL: corruption not detected"; exit 1
fi
echo "ok: corruption detected (CRC)"

HDR=280
block() { tail -c +$((HDR + 256 * $2 + 1)) "$1" | head -c 256; }
fail13() { local rc=0; "$@" 2>/dev/null || rc=$?; [ "$rc" -eq 13 ]; }

# Nine identical plaintext blocks used to make ciphertext block 3 equal DES(k6, 0).
head -c 256 /dev/urandom > "$T/blk"
for i in 1 2 3 4 5 6 7 8 9; do cat "$T/blk"; done > "$T/rep.bin"
./odette act=e in="$T/rep.bin" out="$T/rep.enc" key=sample.key
for i in 0 1 2 3 4 5 6 7 8; do block "$T/rep.enc" $i > "$T/c$i"; done
[ "$(md5sum "$T"/c? | cut -d' ' -f1 | sort -u | wc -l)" -eq 9 ]
for i in 0 1 2 3 4 5 6 7 8; do
  [ "$(od -An -v -tx1 -w8 "$T/c$i" | sort -u | wc -l)" -gt 1 ]
done
echo "ok: repeated plaintext blocks leave no pattern"

./odette act=e in="$T/rep.bin" out="$T/rep2.enc" key=sample.key
for i in 0 1 2 3 4 5 6 7 8; do
  [ "$(cmp -l "$T/c$i" <(block "$T/rep2.enc" $i) | wc -l)" -gt 200 ]
done
echo "ok: random IV makes every block differ between runs"

cp "$T/rep.enc" "$T/t1"
printf '\x55' | dd of="$T/t1" bs=1 seek=$((HDR + 300)) conv=notrunc 2>/dev/null
fail13 ./odette act=d in="$T/t1" out="$T/x" key=sample.key
head -c -256 "$T/rep.enc" > "$T/t2"
fail13 ./odette act=d in="$T/t2" out="$T/x" key=sample.key
cp "$T/rep.enc" "$T/t3"
printf '\x01' | dd of="$T/t3" bs=1 seek=7 conv=notrunc 2>/dev/null
fail13 ./odette act=d in="$T/t3" out="$T/x" key=sample.key
cp "$T/rep.enc" "$T/t4"
printf '\x1e' | dd of="$T/t4" bs=1 seek=4 conv=notrunc 2>/dev/null
fail13 ./odette act=d in="$T/t4" out="$T/x" key=sample.key
echo "ok: bit flip, truncation, header change and oversized KDF parameters fail"

cp "$T/rep.enc" "$T/t5"
printf '\x01' | dd of="$T/t5" bs=1 seek=3 conv=notrunc 2>/dev/null
fail13 ./odette act=d in="$T/t5" out="$T/x" key=sample.key
sed 's/Odette 5\.02/Odette 5.00/' "$T/p.txt" > "$T/old.txt"
rc=0; ./odette act=dm in="$T/old.txt" out="$T/x" key=sample.key 2>/dev/null || rc=$?
[ "$rc" -eq 8 ] || { echo "FAIL: e-mail tags of another version accepted"; exit 1; }
echo "ok: files of another version are rejected"

[ "$(cmp -l <(head -c 24 "$T/rep.enc" | tail -c 16) <(head -c 24 "$T/rep2.enc" | tail -c 16) | wc -l)" -gt 8 ] || { echo "FAIL: salt repeated"; exit 1; }
echo "ok: fresh salt for every encryption"

W="A completely different phrase that is long enough to be accepted."
rc=0; echo "$W" | ./odette act=dm in="$T/p.txt" out="$T/x" phrase 2>/dev/null || rc=$?
[ "$rc" -eq 13 ] || { echo "FAIL: wrong phrase accepted"; exit 1; }
echo "ok: wrong phrase fails authentication"

echo "all tests passed"
