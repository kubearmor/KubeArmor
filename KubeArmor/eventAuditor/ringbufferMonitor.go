// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package eventauditor

import "C"

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"os/signal"

	bpf "github.com/aquasecurity/libbpfgo"
)

type ringbuf_log struct {
	// Ts uint64

	// PidID uint32
	// MntID uint32

	// HostPPID uint32
	// HostPID  uint32

	// PPID uint32
	PID uint32
	UID uint32

	// EventID int32

	Comm [16]byte
}

func RingbufferConsume() {
	bpfModule, err := bpf.NewModuleFromFile("./BPF/objs/ringbuffer.bpf.o")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	bpfModule.BPFLoadObject()

	prog, err := bpfModule.GetProgram("syscall__sys_execve")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	_, err = prog.AttachTracepoint("sched", "sched_process_exec")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	eventsChannel := make(chan []byte)
	rb, err := bpfModule.InitRingBuf("ka_ea_ringbuff_map", eventsChannel)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)
	go func() {
		var log ringbuf_log
		for {
			data := <-eventsChannel
			err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &log)
			if err != nil {
				fmt.Printf("failed to decode received data: %s", err)
				break
			}
			fmt.Printf("Pid: %d \t Uid: %d \t Command: %s \n", log.PID, log.UID, log.Comm)
		}
	}()
	rb.Start()
	<-sig
	rb.Stop()
}
