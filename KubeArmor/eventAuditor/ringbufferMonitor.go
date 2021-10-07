package eventauditor

import "C"

import (
	"encoding/binary"
	"fmt"
	"os"

	lbpf "github.com/kubearmor/libbpf"
)

type log struct {
	PID int
	UID int
}

func (ea *EventAuditor) ringbufferconsume() error {
	var err error

	bpfModule, err := lbpf.OpenObjectFromFile("ringbuffer.bpf.o")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	defer bpfModule.Close()

	bpfModule.Load()
	prog, err := bpfModule.FindProgramByName("sys_enter_execve")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	_, err = prog.AttachKprobe("__x64_sys_execve")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	eventsChannel := make(chan []byte)

	rb, err := bpfModule.InitRingBuf("events", eventsChannel)

	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	rb.Start()
	for {
		eventBytes := <-eventsChannel
		pid := int(binary.LittleEndian.Uint32(eventBytes[0:4])) // Treat first 4 bytes as LittleEndian Uint32
		fmt.Printf("PID %d\n", pid)
	}
	return nil

}
