// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package eventauditor

import "C"

import (
	"encoding/binary"
	"fmt"
	"os"

	lbpf "github.com/kubearmor/libbpf"
)

type log_t struct {
	ts int64

	pid_id uint32
	mnt_id uint32

	host_ppid uint32
	host_pid  uint32

	ppid uint32
	pid  uint32
	uid  uint32

	event_id uint32
}

func (ea *EventAuditor) RingbufferConsume() error {
	var err error

	bpfModule, err := lbpf.OpenObjectFromFile("ringbuffer.bpf.o")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	bpfModule.Load()
	prog, err := bpfModule.FindProgramByName("syscall__sys_execve")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	_, err = prog.AttachKprobe("sched/sched_process_exec")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	eventsChannel := make(chan []byte)

	rb, err := bpfModule.InitRingBuf("ringbuff_map", eventsChannel)

	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	rb.StartPoll()
	for {
		eventBytes := <-eventsChannel
		pid := int(binary.LittleEndian.Uint32(eventBytes[0:4])) // Treat first 4 bytes as LittleEndian Uint32
		fmt.Printf("PID %d\n", pid)
	}
	return nil

}
