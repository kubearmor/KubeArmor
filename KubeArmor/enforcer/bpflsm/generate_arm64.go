//go:build arm64
// +build arm64

package bpflsm

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang process_monitor ../../BPF/process_monitor.bpf.c -- -I/usr/include/ -O2 -g -fno-stack-protector -Wno-missing-declarations -D__TARGET_ARCH_arm64
