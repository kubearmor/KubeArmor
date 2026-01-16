// SPDX-License-Identifier: Apache-2.0
// Copyright 2026  Authors of KubeArmor

package anonmapexec

import "strings"

func ParseProtectionFlags(prot uint64) string {
	var f []string

	if prot&0x1 == 0x1 {
		f = append(f, "PROT_READ")
	}
	if prot&0x2 == 0x2 {
		f = append(f, "PROT_WRITE")
	}
	if prot&0x4 == 0x4 {
		f = append(f, "PROT_EXEC")
	}

	return strings.Join(f, "|")
}

/*
MAP_PRIVATE (0x02): Create a private copy-on-write mapping.
MAP_SHARED (0x01): Share this mapping with all processes that map this object.
MAP_ANONYMOUS (0x20): The mapping is not backed by any file.
MAP_FIXED (0x10): Interpret addr exactly as specified.
MAP_GROWSDOWN (0x1000): Used for stack-like regions.
MAP_DENYWRITE (0x0800): Prevent other processes from writing to this object.
*/

func ParseMemoryFlags(flag uint64) string {
	var f []string

	if flag&0x01 == 0x01 {
		f = append(f, "MAP_SHARED")
	}
	if flag&0x02 == 0x02 {
		f = append(f, "MAP_PRIVATE")
	}
	if flag&0x10 == 0x10 {
		f = append(f, "MAP_FIXED")
	}
	if flag&0x20 == 0x20 {
		f = append(f, "MAP_ANONYMOUS")
	}
	if flag&0x1000 == 0x1000 {
		f = append(f, "MAP_GROWSDOWN")
	}
	if flag&0x0800 == 0x0800 {
		f = append(f, "MAP_DENYWRITE")
	}
	return strings.Join(f, "|")
}
