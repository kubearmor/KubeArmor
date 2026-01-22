// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

// Package probe checks whether the probed LSM support is available.
package probe

import (
	"bytes"
	"encoding/binary"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang probe ../../BPF/probe.bpf.c -- -I/usr/include/ -O2 -g

type eventBPF struct {
	Exec bool
}

// CheckBPFLSMSupport check if BPF LSM support is enabled in the kernel or not by loading a memfd hook and checking if it is executed and a ringbuf event is received
// It returns an error if the kernel does not support BPF LSM
func CheckBPFLSMSupport() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return err
	}

	objs := probeObjects{}
	if err := loadProbeObjects(&objs, nil); err != nil {
		return err
	}
	defer objs.KubearmorEvents.Close()
	defer objs.KubearmorEvents.Unpin()
	defer objs.Close()

	kp, err := link.AttachLSM(link.LSMOptions{Program: objs.TestMemfd})
	if err != nil {
		return err
	}
	defer kp.Close()

	rd, err := ringbuf.NewReader(objs.KubearmorEvents)
	if err != nil {
		return err
	}
	defer rd.Close()

	var event eventBPF
	go func() {
		fd, err := unix.MemfdCreate("trigger_memfd", 0)
		if err != nil {
			return
		}
		defer unix.Close(fd)
	}()

	rd.SetDeadline(time.Now().Add(1 * time.Second))
	record, err := rd.Read()
	if err != nil {
		return err
	}

	return binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event)
}
