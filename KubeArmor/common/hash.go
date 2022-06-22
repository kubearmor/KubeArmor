package common

import "unsafe"

/*
 * This contains Jenkins hash algorithm modified to mactch the hashing in ebpf land.
 * Inspiration sources:
 *
 * https://en.wikipedia.org/wiki/Jenkins_hash_function
 * http://burtleburtle.net/bob/c/lookup3.c
 * https://github.com/torvalds/linux/blob/master/tools/include/linux/jhash.h
 * https://github.com/tildeleb/hashland/blob/46daf2d89bba924a4269f30949050748548effb1/jenkins/jenkins.go
 */

func rot(x, k uint32) uint32 {
	return x<<k | x>>(32-k)
}

func mix(a, b, c uint32) (uint32, uint32, uint32) {
	a -= c
	a ^= rot(c, 4)
	c += b
	b -= a
	b ^= rot(a, 6)
	a += c
	c -= b
	c ^= rot(b, 8)
	b += a
	a -= c
	a ^= rot(c, 16)
	c += b
	b -= a
	b ^= rot(a, 19)
	a += c
	c -= b
	c ^= rot(b, 4)
	b += a

	return a, b, c
}

func final(a, b, c uint32) uint32 {
	c ^= b
	c -= rot(b, 14)
	a ^= c
	a -= rot(c, 11)
	b ^= a
	b -= rot(a, 25)
	c ^= b
	c -= rot(b, 16)
	a ^= c
	a -= rot(c, 4)
	b ^= a
	b -= rot(a, 14)
	c ^= b
	c -= rot(b, 24)

	return c
}

func JHash(k []byte, seed uint32) uint32 {
	var a, b, c uint32

	var length int
	length = len(k)
	a = 0xdeadbeef + uint32(length) + seed
	b, c = a, a

	for ; length > 12; length -= 12 {
		a += *(*uint32)(unsafe.Pointer(&k[0]))
		b += *(*uint32)(unsafe.Pointer(&k[4]))
		c += *(*uint32)(unsafe.Pointer(&k[8]))
		a, b, c = mix(a, b, c)
		k = k[12:]
	}

	switch length {
	case 12:
		a += *(*uint32)(unsafe.Pointer(&k[0]))
		b += *(*uint32)(unsafe.Pointer(&k[4]))
		c += *(*uint32)(unsafe.Pointer(&k[8]))
	case 11:
		c += uint32(k[10]) << 16
		fallthrough
	case 10:
		c += uint32(k[9]) << 8
		fallthrough
	case 9:
		c += uint32(k[8])
		fallthrough
	case 8:
		a += *(*uint32)(unsafe.Pointer(&k[0]))
		b += *(*uint32)(unsafe.Pointer(&k[4]))
		// break
	case 7:
		b += uint32(k[6]) << 16
		fallthrough
	case 6:
		b += uint32(k[5]) << 8
		fallthrough
	case 5:
		b += uint32(k[4])
		fallthrough
	case 4:
		a += *(*uint32)(unsafe.Pointer(&k[0]))
		// break
	case 3:
		a += uint32(k[2]) << 16
		fallthrough
	case 2:
		a += uint32(k[1]) << 8
		fallthrough
	case 1:
		a += uint32(k[0])
		// break
	case 0:
		return c /* zero length strings require no mixing */
	}
	c = final(a, b, c)
	return c
}
