// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

//go:build linux

package monitor

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	cle "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"

	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
)

// initBPFMaps Function
func (mon *SystemMonitor) initBPFMaps() error {
	visibilityMap, errviz := cle.NewMapWithOptions(
		&cle.MapSpec{
			Name:       "kubearmor_visibility",
			Type:       cle.HashOfMaps,
			KeySize:    8,
			ValueSize:  4,
			MaxEntries: 65535,
			Pinning:    cle.PinByName,
			InnerMap:   &mon.BpfVisibilityMapSpec,
		}, cle.MapOptions{
			PinPath: mon.PinPath,
		})
	if errviz != nil {
		mon.Logger.Errf("Error Creating System Monitor Visibility Map : %s", errviz.Error())
		// returning to avoid updates on nil visibility map
		return errviz
	}
	mon.BpfNsVisibilityMap = visibilityMap
	mon.UpdateVisibility()

	bpfConfigMap, errconfig := cle.NewMapWithOptions(
		&cle.MapSpec{
			Name:       "kubearmor_config",
			Type:       cle.Hash,
			KeySize:    4,
			ValueSize:  4,
			MaxEntries: 16,
			Pinning:    cle.PinByName,
			InnerMap:   &mon.BpfVisibilityMapSpec,
		}, cle.MapOptions{
			PinPath: mon.PinPath,
		})
	if errconfig != nil {
		mon.Logger.Errf("Error Creating System Monitor Config Map : %s", errconfig.Error())
		// returning to avoid updates on nil config map
		return errconfig

	}
	mon.BpfConfigMap = bpfConfigMap
	if cfg.GlobalCfg.HostPolicy {
		if err := mon.BpfConfigMap.Update(uint32(0), uint32(1), cle.UpdateAny); err != nil {
			mon.Logger.Errf("Error Updating System Monitor Config Map to enable host visibility : %s", err.Error())
		}
	}
	if cfg.GlobalCfg.Policy {
		if err := mon.BpfConfigMap.Update(uint32(1), uint32(1), cle.UpdateAny); err != nil {
			mon.Logger.Errf("Error Updating System Monitor Config Map to enable container visibility : %s", err.Error())
		}
	}

	mon.UpdateThrottlingConfig()
	mon.UpdateMatchArgsConfig()

	return errors.Join(errviz, errconfig)
}

// DestroyBPFMaps Function
func (mon *SystemMonitor) DestroyBPFMaps() {
	if mon.BpfNsVisibilityMap != nil {
		err := mon.BpfNsVisibilityMap.Unpin()
		if err != nil {
			mon.Logger.Warnf("error unpinning bpf map kubearmor_visibility %v", err)
		}
		err = mon.BpfNsVisibilityMap.Close()
		if err != nil {
			mon.Logger.Warnf("error closing bpf map kubearmor_visibility %v", err)
		}
	}

	if mon.BpfConfigMap != nil {
		err := mon.BpfConfigMap.Unpin()
		if err != nil {
			mon.Logger.Warnf("error unpinning bpf map kubearmor_config %v", err)
		}
		err = mon.BpfConfigMap.Close()
		if err != nil {
			mon.Logger.Warnf("error closing bpf map kubearmor_config %v", err)
		}
	}
}

// InitBPF Function
func (mon *SystemMonitor) InitBPF() error {
	homeDir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		return err
	}

	bpfPath := homeDir + "/BPF/"
	if _, err := os.Stat(filepath.Clean(bpfPath)); err != nil { // #nosec G703 -- trusted
		// go test

		bpfPath = os.Getenv("PWD") + "/../BPF/"
		if _, err := os.Stat(filepath.Clean(bpfPath)); err != nil { // #nosec G703 -- trusted path
			// container

			bpfPath = "/opt/kubearmor/BPF/"
			if _, err := os.Stat(filepath.Clean(bpfPath)); err != nil {
				return err
			}
		}
	}

	mon.Logger.Print("Initializing eBPF system monitor")

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("error removing memlock %v", err)
	}

	bpfPath = bpfPath + "system_monitor.bpf.o"

	err = mon.initBPFMaps()
	if err != nil {
		return err
	}
	mon.Logger.Printf("eBPF system monitor object file path: %s", bpfPath)
	bpfModuleSpec, err := cle.LoadCollectionSpec(bpfPath)
	if err != nil {
		return fmt.Errorf("cannot load bpf module specs %v", err)
	}
	mon.BpfModule, err = cle.NewCollectionWithOptions(
		bpfModuleSpec,
		cle.CollectionOptions{
			Maps: cle.MapOptions{
				PinPath: mon.PinPath,
			},
		},
	)
	if err != nil {
		var verr *cle.VerifierError
		if errors.As(err, &verr) {
			fmt.Printf("Full log: %+v\n", verr)
		}
		return fmt.Errorf("bpf module is nil %v", err)
	}

	mon.Logger.Print("Initialized the eBPF system monitor")

	systemCalls := []string{"open", "openat", "execve", "execveat", "socket", "connect", "bind", "listen", "unlink", "unlinkat", "rmdir", "ptrace", "chown", "setuid", "setgid", "fchownat", "mount", "umount"}
	// {category, event}
	sysTracepoints := [][2]string{{"syscalls", "sys_exit_openat"}, {"syscalls", "sys_enter_setns"}, {"syscalls", "sys_exit_setns"}, {"sched", "sched_process_fork"}}
	sysKprobes := []string{"do_exit", "security_bprm_check", "security_file_open", "security_path_mknod", "security_path_unlink", "security_path_rmdir", "security_ptrace_access_check"}
	netSyscalls := []string{"tcp_connect"}
	netRetSyscalls := []string{"inet_csk_accept", "tcp_connect"}

	if mon.BpfModule != nil {

		mon.Probes = make(map[string]link.Link)

		mon.Probes["kprobe__udp_send_skb"], err = link.Kprobe("udp_send_skb", mon.BpfModule.Programs["kprobe__udp_send_skb"], nil)
		if err != nil {
			mon.Logger.Warnf("error loading kprobe udp_send_skb %v", err)
			delete(mon.Probes, "kprobe__udp_send_skb")
		}

		for _, syscallName := range systemCalls {
			mon.Probes["kprobe__"+syscallName], err = link.Kprobe("sys_"+syscallName, mon.BpfModule.Programs["kprobe__"+syscallName], nil)
			if err != nil {
				mon.Logger.Warnf("error loading kprobe %s: %v", syscallName, err)
				delete(mon.Probes, "kprobe__"+syscallName)
			}

			mon.Probes["kretprobe__"+syscallName], err = link.Kretprobe("sys_"+syscallName, mon.BpfModule.Programs["kretprobe__"+syscallName], nil)
			if err != nil {
				mon.Logger.Warnf("error loading kretprobe %s: %v", syscallName, err)
				delete(mon.Probes, "kretprobe__"+syscallName)
			}

		}

		for _, sysTracepoint := range sysTracepoints {
			mon.Probes[sysTracepoint[1]], err = link.Tracepoint(sysTracepoint[0], sysTracepoint[1], mon.BpfModule.Programs[sysTracepoint[1]], nil)
			if err != nil {
				mon.Logger.Warnf("error:%s: %v", sysTracepoint, err)
				delete(mon.Probes, sysTracepoint[1])
			}
		}

		for _, sysKprobe := range sysKprobes {
			mon.Probes["kprobe__"+sysKprobe], err = link.Kprobe(sysKprobe, mon.BpfModule.Programs["kprobe__"+sysKprobe], nil)
			if err != nil {
				mon.Logger.Warnf("error loading kprobe %s: %v", sysKprobe, err)
				delete(mon.Probes, "kprobe__"+sysKprobe)
			}
		}

		for _, netSyscall := range netSyscalls {
			mon.Probes["kprobe__"+netSyscall], err = link.Kprobe(netSyscall, mon.BpfModule.Programs["kprobe__"+netSyscall], nil)
			if err != nil {
				mon.Logger.Warnf("error loading kprobe %s: %v", netSyscall, err)
				delete(mon.Probes, "kprobe__"+netSyscall)
			}
		}

		for _, netRetSyscall := range netRetSyscalls {
			mon.Probes["kretprobe__"+netRetSyscall], err = link.Kretprobe(netRetSyscall, mon.BpfModule.Programs["kretprobe__"+netRetSyscall], nil)
			if err != nil {
				mon.Logger.Warnf("error loading kretprobe %s: %v", netRetSyscall, err)
				delete(mon.Probes, "kretprobe__"+netRetSyscall)
			}
		}

		mon.SyscallChannel = make(chan []byte, SyscallChannelSize)

		mon.SyscallPerfMap, err = perf.NewReader(mon.BpfModule.Maps["sys_events"], os.Getpagesize()*1024)
		if err != nil {
			mon.Logger.Warnf("error initializing events perf map: %v", err)
		}

		if cfg.GlobalCfg.EnableIMA {
			if err := mon.InitImaHash(); err != nil {
				mon.Logger.Warnf("error initializing IMA hash module: %s", err)
			}
		}
	}

	return nil
}
