// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package enforcer

const (
	AppArmorDefaultPreStart = `

#include <abstractions/base>
umount,
file,
network,
capability,

`
	AppArmorPrivilegedPreStart = AppArmorDefaultPreStart +
		`

## == For privileged workloads == ##
mount,
signal,
unix,
ptrace,

`

	AppArmorPrivilegedPostStart = `

/lib/x86_64-linux-gnu/{*,**} rm,

deny @{PROC}/{*,**^[0-9*],sys/kernel/shm*} wkx,
deny @{PROC}/sysrq-trigger rwklx,
deny @{PROC}/mem rwklx,
deny @{PROC}/kmem rwklx,
deny @{PROC}/kcore rwklx,

deny /sys/[^f]*/** wklx,
deny /sys/f[^s]*/** wklx,
deny /sys/fs/[^c]*/** wklx,
deny /sys/fs/c[^g]*/** wklx,
deny /sys/fs/cg[^r]*/** wklx,
deny /sys/firmware/efi/efivars/** rwklx,
deny /sys/kernel/security/** rwklx,

`

	AppArmorDefaultPostStart = AppArmorPrivilegedPostStart +
		`

deny mount,

`
)
