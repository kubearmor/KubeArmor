// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package eventauditor

import (
	"bytes"
	"encoding/binary"
	"os"
	"os/signal"
	"syscall"

	lbpf "github.com/kubearmor/libbpf"
)

type ringBufferLog struct {
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

// RingbufferConsume Function
func (ea *EventAuditor) RingbufferConsume() {
	var err error
	var log ringBufferLog
	var rb *lbpf.KABPFRingBuffer

	bpfModule := ea.BPFManager.getObj("ringbuffer.bpf.o")
	eventsChannel := make(chan []byte)
	if rb, err = bpfModule.InitRingBuf("ka_ea_ringbuff_map", eventsChannel); err != nil {
		ea.Logger.Errf("Failed to initialize ringbuf: %v", err)
	}

	go func() {
		var ok bool
		var data []byte

		for {
			if data, ok = <-eventsChannel; !ok {
				break
			}

			if err = binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &log); err != nil {
				ea.Logger.Errf("Failed to decode received data: %v", err)
				continue
			}

			// TODO: use ea.Logger.PushLog
			ea.Logger.Printf("DEBUG-EA-LOG: EventPid: %d, Uid: %d, Command: %s", log.PID, log.UID, log.Comm)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT,
		os.Interrupt)

	rb.StartPoll()
	<-sig
	rb.StopPoll()
	rb.Free()
}
