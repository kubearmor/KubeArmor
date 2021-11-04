// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package eventauditor

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"os/signal"
	//bpf "github.com/kubearmor/libbpf"
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

func (ea *EventAuditor) RingbufferConsume() {

	bpfModule := ea.BPFManager.getObj("ringbuffer.bpf.o")

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
				fmt.Printf("failed to decode received data, error: %s\n", err)
				break
			}
			fmt.Printf("Pid: %d \t Uid: %d \t Command: %s\n", log.PID, log.UID, log.Comm)
		}
	}()
	rb.StartPoll()
	<-sig
	rb.StopPoll()
}
