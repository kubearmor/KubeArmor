//go:build amd64
// +build amd64

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package bpflsm

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang process_monitor ../../BPF/process_monitor.bpf.c -- -I/usr/include/ -O2 -g -fno-stack-protector -Wno-missing-declarations -D__TARGET_ARCH_x86
