// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of KubeArmor

package seccomp

var (
	Archx86_64 = "SCMP_ARCH_X86_64"
	Archx86    = "SCMP_ARCH_X86"
	Archx32    = "SCMP_ARCH_X32"
	ArchARM64  = "SCMP_ARCH_AARCH64"
	ArchARM    = "SCMP_ARCH_ARM"

	ActErrno = "SCMP_ACT_ERRNO"
	ActAllow = "SCMP_ACT_ALLOW"
	ActLog   = "SCMP_ACT_LOG"
)

type Syscalls struct {
	Names  []string `json:"names,omitempty"`
	Action string   `json:"action,omitempty"`
}

type Seccomp struct {
	DefaultAction string      `json:"defaultAction,omitempty"`
	Architectures []string    `json:"architectures,omitempty"`
	Syscalls      []*Syscalls `json:"syscalls,omitempty"`
}
