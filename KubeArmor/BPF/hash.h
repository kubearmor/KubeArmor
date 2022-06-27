// +build ignore

#ifndef __HASH_H
#define __HASH_H

#include "vmlinux.h"

/*
 * This contains Jenkins hash algorithm modified for use in ebpf land:
 * jenkins_rot(), jenkins_mix(), jenkins_final() and jenkins_hash()
 *
 * Inspiration sources:
 *
 * https://en.wikipedia.org/wiki/Jenkins_hash_function
 * http://burtleburtle.net/bob/c/lookup3.c
 * https://github.com/torvalds/linux/blob/master/tools/include/linux/jhash.h
 * https://github.com/tildeleb/hashland/blob/46daf2d89bba924a4269f30949050748548effb1/jenkins/jenkins.go
 */

static inline u32 jenkins_rot(u32 x, u32 k) {
  return (x << k) | (x >> (32 - k));
}

static inline void jenkins_mix(u32 *ap, u32 *bp, u32 *cp) {
  u32 a = *ap;
  u32 b = *bp;
  u32 c = *cp;

  a -= c;
  a ^= jenkins_rot(c, 4);
  c += b;
  b -= a;
  b ^= jenkins_rot(a, 6);
  a += c;
  c -= b;
  c ^= jenkins_rot(b, 8);
  b += a;
  a -= c;
  a ^= jenkins_rot(c, 16);
  c += b;
  b -= a;
  b ^= jenkins_rot(a, 19);
  a += c;
  c -= b;
  c ^= jenkins_rot(b, 4);
  b += a;

  *ap = a;
  *bp = b;
  *cp = c;
}

static inline void jenkins_final(u32 a, u32 b, u32 *cp) {
  u32 c = *cp;

  c ^= b;
  c -= jenkins_rot(b, 14);
  a ^= c;
  a -= jenkins_rot(c, 11);
  b ^= a;
  b -= jenkins_rot(a, 25);
  c ^= b;
  c -= jenkins_rot(b, 16);
  a ^= c;
  a -= jenkins_rot(c, 4);
  b ^= a;
  b -= jenkins_rot(a, 14);
  c ^= b;
  c -= jenkins_rot(b, 24);

  *cp = c;
}

static u32 jenkins_hash(const char *key, u32 length, u32 initval) {
  const u8 *k = (const u8 *)key;
  u32 a, b, c;

  a = 0xdeadbeef + length + initval;
  b = a;
  c = a;

  while (length > 12) {
    a += *((u32 *)&k[0]);
    b += *((u32 *)&k[4]);
    c += *((u32 *)&k[8]);
    jenkins_mix(&a, &b, &c);
    length -= 12;
    k += 12;
  }

  switch (length) {
  case 12:
    a += *((u32 *)&k[0]);
    b += *((u32 *)&k[4]);
    c += *((u32 *)&k[8]);
    break;
  case 11:
    c += ((u32)k[10]) << 16;
    /* fallthrough */
  case 10:
    c += ((u32)k[9]) << 8;
    /* fallthrough */
  case 9:
    c += ((u32)k[8]);
    /* fallthrough */
  case 8:
    a += *((u32 *)&k[0]);
    b += *((u32 *)&k[4]);
    break;
  case 7:
    b += ((u32)k[6]) << 16;
    /* fallthrough */
  case 6:
    b += ((u32)k[5]) << 8;
    /* fallthrough */
  case 5:
    b += ((u32)k[4]);
    /* fallthrough */
  case 4:
    a += *((u32 *)&k[0]);
    break;
  case 3:
    a += ((u32)k[2]) << 16;
    /* fallthrough */
  case 2:
    a += ((u32)k[1]) << 8;
    /* fallthrough */
  case 1:
    a += ((u32)k[0]);
    break;
  case 0:
    return c;
  }

  jenkins_final(a, b, &c);

  return c;
}

#endif /* __HASH_H */