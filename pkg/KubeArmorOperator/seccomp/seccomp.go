// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of KubeArmor

package seccomp

import (
	"encoding/json"
	//"github.com/containers/common/pkg/seccomp"
	"github.com/kubearmor/KubeArmor/KubeArmor/log"
	"os"
	"path/filepath"
)

var seccompPath = "/var/lib/kubelet/seccomp"

// LoadSeccompInNode loads seccomp
func LoadSeccompInNode() {

	seccompProfile := Seccomp{
		DefaultAction: ActErrno,
		Architectures: []string{Archx32, Archx86_64, Archx86, ArchARM, ArchARM64},
		Syscalls: []*Syscalls{{
			Names: []string{
				"getsockopt",
				"epoll_ctl",
				"capget",
				"fstat",
				"mmap",
				"fstatfs",
				"bpf",
				"utimensat",
				"memfd_create",
				"prlimit64",
				"open",
				"getgid",
				"dup2",
				"sigaltstack",
				"clone",
				"stat",
				"read",
				"newfstatat",
				"setgroups",
				"sched_getaffinity",
				"wait4",
				"munmap",
				"accept4",
				"mprotect",
				"futex",
				"prctl",
				"gettid",
				"getsockname",
				"exit_group",
				"rt_sigaction",
				"readlinkat",
				"getcwd",
				"execve",
				"madvise",
				"dup",
				"fcntl",
				"close",
				"write",
				"setuid",
				"ioctl",
				"readv",
				"writev",
				"uname",
				"nanosleep",
				"socket",
				"bind",
				"capset",
				"getrlimit",
				"epoll_create1",
				"pread64",
				"eventfd2",
				"dup3",
				"brk",
				"getuid",
				"pipe",
				"chdir",
				"statfs",
				"unlinkat",
				"kill",
				"rt_sigreturn",
				"geteuid",
				"getrandom",
				"getpgid",
				"openat",
				"setgid",
				"getpid",
				"tgkill",
				"fsync",
				"faccessat2",
				"sched_yield",
				"getpeername",
				"setsockopt",
				"rt_sigprocmask",
				"connect",
				"perf_event_open",
				"access",
				"getdents64",
				"epoll_wait",
				"fork",
				"rename",
				"set_tid_address",
				"getpgrp",
				"getppid",
				"pipe2",
				"epoll_pwait",
				"waitid",
				"arch_prctl",
				"listen",
				"lseek",
				"getegid",
				"mkdirat",
				"sendfile",
				"mount",
				"vfork",
				"recvmsg",
				"sendto",
				"recvfrom",
			},
			Action: ActAllow,
		},
		},
	}

	seccompInitProfile := Seccomp{
		DefaultAction: ActErrno,
		Architectures: []string{Archx32, Archx86_64, Archx86, ArchARM, ArchARM64},
		Syscalls: []*Syscalls{{
			Names: []string{
				"dup2",
				"epoll_ctl",
				"getdents64",
				"pread64",
				"geteuid",
				"newfstatat",
				"memfd_create",
				"capset",
				"read",
				"dup3",
				"getpgid",
				"getrandom",
				"close",
				"fchown",
				"mremap",
				"unlinkat",
				"readlink",
				"sigaltstack",
				"getegid",
				"arch_prctl",
				"lseek",
				"fstat",
				"getppid",
				"faccessat2",
				"munmap",
				"getpgrp",
				"clone",
				"setgroups",
				"prlimit64",
				"getpid",
				"set_tid_address",
				"getuid",
				"rt_sigaction",
				"rt_sigreturn",
				"socket",
				"chdir",
				"capget",
				"sysinfo",
				"connect",
				"pipe2",
				"openat",
				"access",
				"set_robust_list",
				"fstatfs",
				"setuid",
				"ioctl",
				"futex",
				"pipe",
				"mmap",
				"getgid",
				"rt_sigprocmask",
				"wait4",
				"exit_group",
				"uname",
				"write",
				"prctl",
				"fcntl",
				"setgid",
				"brk",
				"getcwd",
				"execve",
				"mprotect",
				"rseq",
				"recvmsg",
				"faccessat",
				"clone3",
				"setresuid",
				"setresgid",
				"statfs",
				"fadvise64",
				"copy_file_range",
			},
			Action: ActAllow,
		},
		},
	}

	jsonData, err := json.MarshalIndent(seccompProfile, "", "    ")
	jsonInitData, err := json.MarshalIndent(seccompInitProfile, "", "    ")
	if err != nil {
		log.Errf("Error marshaling JSON: %s", err.Error())

	}

	if err := os.WriteFile(seccompPath+"/kubearmor-seccomp.json", jsonData, 0664); err != nil {
		log.Errf("Error copying file to seccomp directory: %s", err.Error())
	}

	if err := os.WriteFile(seccompPath+"/kubearmor-init-seccomp.json", jsonInitData, 0664); err != nil {
		log.Errf("Error copying file to seccomp directory: %s", err.Error())
	}
}

func CheckIfSeccompProfilePresent() string {
	_, err1 := os.Stat(filepath.Clean(seccompPath + "/kubearmor-init-seccomp.json"))
	_, err2 := os.Stat(filepath.Clean(seccompPath + "/kubearmor-seccomp.json"))

	if err1 == nil && err2 == nil {
		return "yes"
	}

	return "no"
}
