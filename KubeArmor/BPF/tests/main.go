// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

// This program loads an eBPF program to test if the probe is supported by the kernel.
package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	cle "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func main() {

	args := os.Args[1:]
	if len(args) != 1 {
		log.Fatalf("Unexpected arg number, expected 1 got %d\n", len(args))
	}
	syscall := strings.Split(args[0], "/")[1] // syscall name

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	bpfModule, err := cle.LoadCollection(args[0] + ".bpf.o")
	if err != nil {
		log.Fatalf("bpf module is nil %v\n", err)
	}

	var fn string
	count := 0
	for k := range bpfModule.Programs {
		fn = k
		count++
	}

	if count != 1 {
		log.Fatalf("%s.c should contain only one syscall\n", args[0])
	}

	if strings.HasPrefix(fn, "Kprobe__") {
		_, err = link.Kprobe(syscall, bpfModule.Programs[fn], nil)
		if err != nil {
			log.Fatalf("[Failed] Cannot attach syscall %s\n", err.Error())
		}
	} // other probe types goes here
	/*else if (){

	}*/

	fmt.Printf("[Success] Syscall %s attahed\n", fn)
}
