// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package eventauditor

import lbpf "github.com/kubearmor/libbpf"

// KAEAGetEntryPointProg Function
func KAEAGetEntryPointProg(name string) KABPFProg {
	switch name {
	case "execve":
		return KABPFProg{
			Name:      KABPFProgName("syscall__sys_" + name),
			EventName: KABPFEventName("syscalls:sys_enter_" + name),
			EventType: lbpf.KABPFLinkTypeTracepoint,
			FileName:  KABPFObjFileName("entrypoint.bpf.o"),
		}
	case "execveat":
		return KABPFProg{
			Name:      KABPFProgName("syscall__sys_" + name),
			EventName: KABPFEventName("syscalls:sys_enter_" + name),
			EventType: lbpf.KABPFLinkTypeTracepoint,
			FileName:  KABPFObjFileName("entrypoint.bpf.o"),
		}
	case "open":
		return KABPFProg{
			Name:      KABPFProgName("syscall__sys_" + name),
			EventName: KABPFEventName("syscalls:sys_enter_" + name),
			EventType: lbpf.KABPFLinkTypeTracepoint,
			FileName:  KABPFObjFileName("entrypoint.bpf.o"),
		}
	case "openat":
		return KABPFProg{
			Name:      KABPFProgName("syscall__sys_" + name),
			EventName: KABPFEventName("syscalls:sys_enter_" + name),
			EventType: lbpf.KABPFLinkTypeTracepoint,
			FileName:  KABPFObjFileName("entrypoint.bpf.o"),
		}
	case "socket":
		return KABPFProg{
			Name:      KABPFProgName("syscall__sys_" + name),
			EventName: KABPFEventName("syscalls:sys_enter_" + name),
			EventType: lbpf.KABPFLinkTypeTracepoint,
			FileName:  KABPFObjFileName("entrypoint.bpf.o"),
		}
	case "connect":
		return KABPFProg{
			Name:      KABPFProgName("syscall__sys_" + name),
			EventName: KABPFEventName("syscalls:sys_enter_" + name),
			EventType: lbpf.KABPFLinkTypeTracepoint,
			FileName:  KABPFObjFileName("entrypoint.bpf.o"),
		}
	case "accept":
		return KABPFProg{
			Name:      KABPFProgName("syscall__sys_" + name),
			EventName: KABPFEventName("syscalls:sys_enter_" + name),
			EventType: lbpf.KABPFLinkTypeTracepoint,
			FileName:  KABPFObjFileName("entrypoint.bpf.o"),
		}
	case "bind":
		return KABPFProg{
			Name:      KABPFProgName("syscall__sys_" + name),
			EventName: KABPFEventName("syscalls:sys_enter_" + name),
			EventType: lbpf.KABPFLinkTypeTracepoint,
			FileName:  KABPFObjFileName("entrypoint.bpf.o"),
		}
	case "listen":
		return KABPFProg{
			Name:      KABPFProgName("syscall__sys_" + name),
			EventName: KABPFEventName("syscalls:sys_enter_" + name),
			EventType: lbpf.KABPFLinkTypeTracepoint,
			FileName:  KABPFObjFileName("entrypoint.bpf.o"),
		}
	default:
		return KABPFProg{
			Name:      "",
			EventName: "",
			EventType: lbpf.KABPFLinkTypeUnspec,
			FileName:  "",
		}
	}
}
