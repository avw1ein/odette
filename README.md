# Odette 5.02

Copyright (C) by Andy van Wezel, 1993 - 1994, 2026.
Released under the MIT License (see [LICENSE](LICENSE)).

## Contents

- [Introduction](#introduction)
- [History](#history)
- [Ethics](#ethics)

1. [Quick start](#1-quick-start)
2. [Why use Odette?](#2-why-use-odette)
3. [How does it work?](#3-how-does-it-work)
4. [The encryption scheme](#4-the-encryption-scheme)
5. [How to use Odette with e-mail software](#5-how-to-use-odette-with-e-mail-software)
6. [How to use Odette normal style](#6-how-to-use-odette-normal-style)
7. [Keys](#7-keys)
8. [Intramural security](#8-intramural-security)
9. [Don't](#9-dont)
10. [Error levels](#10-error-levels)
11. [Disclaimer](#11-disclaimer)

---

## Introduction

**THIS IS A HOBBY PROJECT**

Odette gives you a way to protect your data, whether you keep it at home or send it throughout the world. The program provides two sorts of output, High-ASCII and Low-ASCII. You can use the first for security at home. The second one is aimed at e-mail.

The program uses the Data Encryption Standard (DES). See section 2 for the reasoning behind this choice.

Features:

- DES eight times over, with 2048-bit whitening between layers.
- A 2048-bit tweak per block, so every block is encrypted by its own instance of the cipher.
- HMAC-SHA-512 authentication (512-bit key and tag), checked before decryption.
- CRC-32 check on e-mail output.
- Key phrase (scrypt, salted) or key file.
- Easy to use.
- Slow! Which is good!

---

## History

The first experiments with block expansion, the novelty in this project, were done in the early nineties. Back then the USA lifted the export embargo on DES. Note that this project started before AES. If you're interested, have a look at the first AES stage. Big Blue, IBM, placed an example implementation of DES into the public domain. I found it on Fidonet. My first program was called Lowkeyed. Lowkeyed used a home-brew DES3 variant based on block expansion. To transport cipher text in e-mails, I added a translation to low-ASCII. Hence, low-keyed. This translation was common in those days, since e-mail attachments only came later. Then came the General Privacy Guard, GPG. GPG used 6 layers of DES. I kept developing the project inside my head, but didn't make updates for a long time. GPG is nowadays a synonym for GnuPG and not General Privacy Guard. So here comes Odette! Odette is an ode to Tchaikovsky's Swan Lake.

---

## Ethics

Technology doesn't discriminate against its usage and users. I've learned to exaggerate to make a point. Here we go: at the end of WWII people were convinced they needed the A-bomb (first). Ever since, governments and their institutes have worked round the clock to prevent bad actors from pushing the button. The world has already had some near escapes.

Currently, Odette is in the ballpark of AES-256, if not 512. Its predecessors already had that potential. For a long time this gave me a bad gut feeling. Today, however, with quantum computers around the corner and also a stronger link between human rights and encryption, I no longer feel uneasy about continuing.

---

## 1. Quick start

For a quick e-mail style demonstration:

```sh
./odette act=dm in=hello.ode out=hello.txt key=sample.key
cat hello.txt
```

`hello.txt`, `hello.ode` and `sample.key` are ASCII files.

For a quick demonstration in normal style, encrypt and decrypt a file:

```sh
./odette act=e in=myfile out=myfile.ode key=sample.key
./odette act=d in=myfile.ode out=myfile.out key=sample.key
```

To see how to make a key file:

```sh
cat sample.key
```

To get help:

```sh
./odette
```

Files made by Odette 5.02 cannot be read by older versions, and the other way around.

---

## 2. Why use Odette?

At this moment a single DES encryption can be cracked in a few hours (minutes?). You need a good computer to do it, but... The next step in line is triple DES (DES3). This is also within reach of modern computers. That's why some of us need something stronger. Odette is just that. In return you have to be more patient, because it is slower. This slow speed actually makes brute-force attacks more difficult, compared to more modern, more optimized algorithms. Nowadays almost every CPU, for example, has AES acceleration. This accelerates brute-force attacks on AES.

The eight keys feed eight DES layers and a 2048-bit whitening that is derived from every bit of every key. Without the whitening, a meet-in-the-middle attack on a cascade of eight ciphers would need about 2^224 operations. The whitening keeps both halves of such an attack from being tried alone, so the best known approach is to try all 2^512 key values. This is an estimate, not a proof, and the construction has not been reviewed by others. A phrase is only as strong as its entropy: ordinary text carries about 1 to 1.5 bits per character, so use a long phrase or a key file with random keys.

Don't think single DES is bad just because it can be cracked. In the end every code can be cracked; it's just a matter of resources. DES has been studied for almost 50 years. Its security properties, including the shortcomings, are well known. This is the reason why DES can be used as a building block for something stronger. Instead of beginning from scratch, Odette can rely on all that is known about DES.

Is Odette an invention? It's more a matter of creativity. It mostly uses well-known techniques to reach its goal. You should see it as an interface to DES. The creativity is in the block expansion technique that makes multiple DES iterations worthwhile. The block cipher is scaled up and slowed down. Both are great properties for security.

---

## 3. How does it work?

Encryption is done in independent steps. Besides the DES steps there are block expansion steps. The block expansion steps widen the block to 2048 bits and spread every input bit over the whole block. They are keyless, so they do not add key strength.

Total encryption is performed on 2048-bit blocks. Standard DES uses 64-bit blocks and has a key space of 2^56. Odette uses eight 64-bit keys, 2^512 values in all (see section 2).

The strength of a code is not only measured by its key space. But in the case of DES we know for sure that it's a strong code that only needs expansion.

On completion of encryption, the result can be translated into Low-ASCII (e-mail style) using the following characters:

```
0123456789:; ABCDEFGHIJKLMNOPQRSTUVWXYZ abcdefghijklmnopqrstuvwxyz
```

This makes the output file about 133% of the size of the input file. Very small files will grow more. Start and end lines are added, and also a newline (LF) after every 60th character.

---

## 4. The encryption scheme

Encryption is performed in sixteen steps.

Block expansion swaps the upper 4 bits of a byte in the first half block with the lower 4 bits of the corresponding byte in the second half block. Thus, to decrypt the first half block, you must include the second half block as well, and vice versa.

Although DES is supposed to have a multiplying property, Odette doesn't rely on it. Block expansion inputs new data in each 64-bit block before a new encryption is done.

```
Step  0: Rounding the file size up to a multiple of 256 bytes.
         The missing bytes are filled up with random information
         from the system random generator; the last byte holds
         the masked length. Every 256-byte block is then XORed
         with the previous ciphertext block (a random 256-byte
         IV for the first one) and with a 2048-bit tweak that is
         unique to that block, and goes through steps 1-16. The
         same tweak is XORed into the result. This is Cipher
         Block Chaining (CBC) around the whole cipher, with a
         different cipher instance for every block, so no two
         blocks are ever encrypted by the same permutation.
Step  1: Block expansion 2048 bits.
Step  2: Whitening 1, DES encryption with key1.
Step  3: Block expansion 128 bits.
Step  4: Whitening 2, DES encryption with key2.
Step  5: Block expansion 256 bits.
Step  6: Whitening 3, DES encryption with key3.
Step  7: Block expansion 512 bits.
Step  8: Whitening 4, DES encryption with key4.
Step  9: Block expansion 1024 bits.
Step 10: Whitening 5, DES encryption with key5.
Step 11: Block expansion 2048 bits.
Step 12: Whitening 6, DES encryption with key6.
Step 13: Block expansion 128 bits.
Step 14: Whitening 7, DES encryption with key7.
Step 15: Block expansion 256 bits.
Step 16: Whitening 8, DES encryption with key8, then a final
         whitening 9.
```

Each whitening is 2048 bits and is made from all eight keys and the salt with HMAC-SHA-512, so every bit of every key matters, including the bits that DES itself ignores, and two files made with the same key file share no whitening. The tweak of step 0 is made the same way from the keys, the salt and the block number.

The output consists of: a 4-byte header (O, D, 5, 2), the phrase hashing parameters (4 bytes), the salt (16 bytes), the IV (256 bytes), the encrypted blocks, and a 64-byte HMAC-SHA-512 tag over all of it. The MAC key is 512 bits, taken from the same keys or phrase as the DES keys. Decryption checks the tag first and stops with error 13 if it does not match.

The salt and the IV come from the system random generator on every encryption; there is no option to choose or repeat them, and the program stops with error 14 if the generator fails. Encrypting the same file twice therefore gives two unrelated outputs. This is deliberate: it is what guarantees that no two blocks, in one file or across files, are ever encrypted by the same cipher instance.

---

## 5. How to use Odette with e-mail software

Encrypt whatever you like to transmit, using the `act=em` option. Copy the result into a message, and send the message. The recipient must export the message into a file, and decrypt that file using the `act=dm` option. Odette can search for the code in the file, since the code is encapsulated by identification lines.

---

## 6. How to use Odette normal style

Encrypt using the `act=e` option, and decrypt using the `act=d` option. The output file now contains High-ASCII and should be treated as binary data.

---

## 7. Keys

There are two sorts of keys. The first is made by putting eight keys in a key file and keeping that key file. Use random keys.

```sh
key=sample.key
```

Examine the file `sample.key` to see how to construct a key file. It's an ASCII file.

**NEVER use `sample.key` for real data.** It is published together with this program, so anyone can decrypt what you encrypt with it. It is meant for the demonstration in section 1 only. Make your own key file with random keys.

The second sort is made by putting the `phrase` option on the command line. The program will prompt you for a phrase. You must pick a phrase you can always remember, but it shouldn't be an obvious one. The phrase must consist of 48 characters or more. The keys are derived with scrypt, a slow function that needs 128 MiB of memory, and a random salt, so the same phrase gives different keys for every file. Making a guess costs an attacker that memory as well.

> We all thank Andy van Wezel very much, for allowing us to use his wonderful software. We even like to send him money.

Because it's in this document, you should never use the above phrase. You can, however, use a phrase from a book or a film. Please note the entropy remark concerning a phrase in section 2.

At decryption, type the phrase exactly the way you did at encryption. You can use every character your computer accepts.

---

## 8. Intramural security

This kind of security is not trivial because, for example, original files won't be destroyed. If you work on a computer connected to a LAN or WAN, it's also possible for someone else to peek at your computer. Odette disables core dumps, blocks debugger attachment by other processes of your user, and erases keys and the phrase from memory when it is done with them, but it cannot stop the system from swapping its memory to disk. Also read the remark in [ANALYSIS.md](ANALYSIS.md) about cache timing attacks during encryption.

---

## 9. Don't

Here's an incomplete list of what you shouldn't do:

- Don't send keys through insecure channels.
- Don't use the same key over and over again.
- Don't write your keys on your keyboard.
- Don't share your keys with others, unless they need them.

---

## 10. Error levels

The program can generate fourteen error levels. You can use these in a shell script or in a parent program.

| Level | Meaning |
|------:|---------|
| 0 | Normal program termination. |
| 1 | Unable to read from a certain file. |
| 2 | Unable to write to a certain file. |
| 3 | Wrong number of parameters. |
| 4 | Wrong option. |
| 5 | Faulty key file. |
| 6 | Input file and output file must differ. |
| 7 | Not enough memory. |
| 8 | Can't find beginning of code. |
| 9 | Duplicate argument on command line. |
| 10 | Argument missing on command line. |
| 11 | Can't find end of code. |
| 12 | CRC error, e-mail style only. |
| 13 | Authentication failed: wrong key, or data damaged or altered. |
| 14 | System random generator failed. |

---

## 11. Disclaimer

Odette performs a DES8 encryption (works on 2048-bit blocks) on text files or executables. Intramural security is not trivial.

The Data Encryption Standard (DES) was issued by the U.S. National Bureau of Standards.

Odette is free of charge, and provided as is. Andy van Wezel makes no claims and offers no warranties of any sort with Odette. Andy van Wezel also assumes no responsibility for any sort of damage resulting from apparent or actual use of Odette. The user accepts all responsibility for the use and distribution of the program. In some countries there are laws concerning encryption.

Odette is released under the MIT License; see the [LICENSE](LICENSE) file for the full terms. You may use, copy, modify, merge, publish, distribute, sublicense and sell copies of it, provided the copyright and permission notice are kept in all copies or substantial portions of the software.
