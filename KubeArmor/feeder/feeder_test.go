// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package feeder

import (
	"reflect"
	"sync"
	"testing"

	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
	pb "github.com/kubearmor/KubeArmor/protobuf"
)

func TestFeeder(t *testing.T) {
	// node
	node := tp.Node{}
	nodeLock := new(sync.RWMutex)

	// load configuration
	if err := cfg.LoadConfig(); err != nil {
		t.Log("[FAIL] Failed to load configuration")
		return
	}

	// create logger
	logger := NewFeeder(&node, &nodeLock)
	if logger == nil {
		t.Log("[FAIL] Failed to create logger")
		return
	}
	t.Log("[PASS] Created logger")

	// destroy logger
	if err := logger.DestroyFeeder(); err != nil {
		t.Log("[FAIL] Failed to destroy logger")
		return
	}
	t.Log("[PASS] Destroyed logger")
}

func TestMarshalVisibilityLog(t *testing.T) {
	// example visibility log - hostname field excluded since it is set
	// in the feeder and this test just checks marshaling
	visibilityLog := tp.Log{
		ClusterName:       "default",
		Type:              "HostLog",
		Source:            "/usr/bin/dockerd",
		Resource:          "/usr/bin/runc --version",
		Operation:         "Process",
		Data:              "syscall=SYS_EXECVE",
		Result:            "Passed",
		HostPID:           193088,
		HostPPID:          914,
		PID:               193088,
		PPID:              914,
		ParentProcessName: "/usr/bin/dockerd",
		ProcessName:       "/usr/bin/runc",
	}

	expectedMarshaledLog := &pb.Log{
		ClusterName:       "default",
		Type:              "HostLog",
		Source:            "/usr/bin/dockerd",
		Resource:          "/usr/bin/runc --version",
		Operation:         "Process",
		Data:              "syscall=SYS_EXECVE",
		Result:            "Passed",
		HostPID:           193088,
		HostPPID:          914,
		PID:               193088,
		PPID:              914,
		ParentProcessName: "/usr/bin/dockerd",
		ProcessName:       "/usr/bin/runc",
	}

	t.Run("WithResource", func(t *testing.T) {
		originalDropResource := cfg.GlobalCfg.DropResourceFromProcessLogs
		defer func() { cfg.GlobalCfg.DropResourceFromProcessLogs = originalDropResource }()
		cfg.GlobalCfg.DropResourceFromProcessLogs = false

		marshaledLog := MarshalVisibilityLog(visibilityLog)
		if !reflect.DeepEqual(marshaledLog, expectedMarshaledLog) {
			t.Errorf("[FAIL] Expected marshaled log: %+v\nGot: %+v", expectedMarshaledLog, marshaledLog)
		}
	})

	t.Run("WithoutResource", func(t *testing.T) {
		originalDropResource := cfg.GlobalCfg.DropResourceFromProcessLogs
		defer func() { cfg.GlobalCfg.DropResourceFromProcessLogs = originalDropResource }()
		cfg.GlobalCfg.DropResourceFromProcessLogs = true

		expectedWithoutResource := &pb.Log{}
		*expectedWithoutResource = *expectedMarshaledLog
		expectedWithoutResource.Resource = ""

		marshaledLog := MarshalVisibilityLog(visibilityLog)
		if !reflect.DeepEqual(marshaledLog, expectedWithoutResource) {
			t.Errorf("[FAIL] Expected marshaled log: %+v\nGot: %+v", expectedWithoutResource, marshaledLog)
		}
	})
}
