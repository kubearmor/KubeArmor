// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package eventauditor

import lbpf "github.com/kubearmor/libbpf"

// KubeArmor Event Auditor Programs
const (
	KAEASysExecveProg     KABPFProgName    = "ka_ea_sys_execve"
	KAEASysExecveEvent    KABPFEventName   = "syscalls:sys_enter_execve"
	KAEASysExecveProgFile KABPFObjFileName = "ka_ea_process_prog.bpf.o"

	KAEASysExitProg     KABPFProgName    = "ka_ea_sys_exit"
	KAEASysExitEvent    KABPFEventName   = "syscalls:sys_enter_exit"
	KAEASysExitProgFile KABPFObjFileName = "ka_ea_process_prog.bpf.o"
)

// KAEAGetProg Function
func KAEAGetProg(name KABPFProgName) KABPFProg {
	switch name {
	case KAEASysExecveProg:
		return KABPFProg{
			Name:      KAEASysExecveProg,
			EventName: KAEASysExecveEvent,
			EventType: lbpf.KABPFLinkTypeTracepoint,
			FileName:  KAEASysExecveProgFile,
		}
	case KAEASysExitProg:
		return KABPFProg{
			Name:      KAEASysExitProg,
			EventName: KAEASysExitEvent,
			EventType: lbpf.KABPFLinkTypeTracepoint,
			FileName:  KAEASysExitProgFile,
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
