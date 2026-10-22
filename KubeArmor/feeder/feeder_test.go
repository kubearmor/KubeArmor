// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package feeder

import (
	"fmt"
	"net"
	"os"
	"reflect"
	"strconv"
	"sync"
	"testing"

	"github.com/kubearmor/KubeArmor/KubeArmor/common"
	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
	pb "github.com/kubearmor/KubeArmor/protobuf"
)

var baseCfg cfg.KubearmorConfig

func cloneConfig() cfg.KubearmorConfig {
	c := baseCfg

	if v := cfg.GlobalCfg.ConfigUntrackedNs.Load(); v != nil {
		c.ConfigUntrackedNs.Store(v)
	}

	if baseCfg.LsmOrder != nil {
		c.LsmOrder = make([]string, len(baseCfg.LsmOrder))
		copy(c.LsmOrder, baseCfg.LsmOrder)
	}

	return c
}

func destroyFeederIfExists(fd *Feeder, t *testing.T) {
	if fd != nil {
		if err := fd.DestroyFeeder(); err != nil {
			t.Logf("Failed to destroy feeder: %v", err)
		}
	}
}

// setup once for this package
func TestMain(m *testing.M) {
	if err := cfg.LoadConfig(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load configuration: %v\n", err)
		os.Exit(1)
	}
	baseCfg = cfg.GlobalCfg

	exitCode := m.Run()

	os.Exit(exitCode)
}

func TestNewFeeder(t *testing.T) {
	tests := []struct {
		name      string
		setup     func(t *testing.T)
		expectNil bool
	}{
		{
			name: "DefaultConfigSuccess",
			setup: func(t *testing.T) {
				cfg.GlobalCfg = cloneConfig()
				cfg.GlobalCfg.GRPC = "55555"
			},
			expectNil: false,
		},
		{
			name: "WithValidLogPath",
			setup: func(t *testing.T) {
				cfg.GlobalCfg = cloneConfig()
				cfg.GlobalCfg.GRPC = "55555"

				tmpFile, err := os.CreateTemp("", "feeder-log-*.log")
				if err != nil {
					t.Fatalf("Failed to create temp log file: %v", err)
				}
				logPath := tmpFile.Name()
				cfg.GlobalCfg.LogPath = logPath

				tmpFile.Close()

				t.Cleanup(func() {
					if err := os.Remove(logPath); err != nil {
						t.Logf("Failed to delete temp log file: %v", err)
					}
				})
			},
			expectNil: false,
		},
		{
			name: "WithInvalidLogPath",
			setup: func(t *testing.T) {
				cfg.GlobalCfg = cloneConfig()
				cfg.GlobalCfg.GRPC = "55555"
				// directory cannot be opened as file
				dir := t.TempDir()
				cfg.GlobalCfg.LogPath = dir
			},
			expectNil: true,
		},
		{
			name: "TLSCredentialsFailure",
			setup: func(t *testing.T) {
				cfg.GlobalCfg = cloneConfig()
				cfg.GlobalCfg.TLSEnabled = true
				cfg.GlobalCfg.GRPC = "55555"
				cfg.GlobalCfg.TLSCertPath = "/invalid/cert.pem"
			},
			expectNil: true,
		},
		{
			name: "GRPCPortInUseFailure",
			setup: func(t *testing.T) {
				cfg.GlobalCfg = cloneConfig()

				listener, err := net.Listen("tcp", ":0")
				if err != nil {
					t.Fatalf("Failed to bind test port: %v", err)
				}
				addr := listener.Addr().(*net.TCPAddr)

				cfg.GlobalCfg.GRPC = strconv.Itoa(addr.Port)

				t.Cleanup(func() {
					listener.Close()
				})
			},
			expectNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup(t)

			node := tp.Node{}
			nodeLock := new(sync.RWMutex)

			feeder := NewFeeder(&node, &nodeLock)
			defer destroyFeederIfExists(feeder, t)

			if tt.expectNil && feeder != nil {
				t.Fatalf("expected feeder to be nil")
			}

			if !tt.expectNil && feeder == nil {
				t.Fatalf("expected feeder to be created")
			}
		})
	}
}

func TestEventStructs_AddAndRemove(t *testing.T) {
	tests := []struct {
		name       string
		addFunc    func(*EventStructs, string, int) (string, any)
		removeFunc func(*EventStructs, string)
		getLen     func(*EventStructs) int
	}{
		{
			name: "AddRemoveMsgStruct",
			addFunc: func(es *EventStructs, filter string, size int) (string, any) {
				return es.AddMsgStruct(filter, size)
			},
			removeFunc: func(es *EventStructs, uid string) {
				es.RemoveMsgStruct(uid)
			},
			getLen: func(es *EventStructs) int {
				return len(es.MsgStructs)
			},
		},
		{
			name: "AddRemoveAlertStruct",
			addFunc: func(es *EventStructs, filter string, size int) (string, any) {
				return es.AddAlertStruct(filter, size)
			},
			removeFunc: func(es *EventStructs, uid string) {
				es.RemoveAlertStruct(uid)
			},
			getLen: func(es *EventStructs) int {
				return len(es.AlertStructs)
			},
		},
		{
			name: "AddRemoveLogStruct",
			addFunc: func(es *EventStructs, filter string, size int) (string, any) {
				return es.AddLogStruct(filter, size)
			},
			removeFunc: func(es *EventStructs, uid string) {
				es.RemoveLogStruct(uid)
			},
			getLen: func(es *EventStructs) int {
				return len(es.LogStructs)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			es := &EventStructs{
				MsgStructs:   make(map[string]EventStruct[pb.Message]),
				AlertStructs: make(map[string]EventStruct[pb.Alert]),
				LogStructs:   make(map[string]EventStruct[pb.Log]),
			}

			uid, ch := tt.addFunc(es, "test-filter", 5)
			if uid == "" {
				t.Fatalf("expected non-empty uid")
			}
			if ch == nil {
				t.Fatalf("expected non-nil channel")
			}

			if got := tt.getLen(es); got != 1 {
				t.Fatalf("expected 1 entry, got %d", got)
			}

			tt.removeFunc(es, uid)
			if got := tt.getLen(es); got != 0 {
				t.Fatalf("expected 0 entries after remove, got %d", got)
			}
		})
	}
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
		ExecEvent:         tp.ExecEvent{},
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
		ExecEvent:         &pb.ExecEvent{},
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

func TestAlertThrottlingAppArmor(t *testing.T) {
	cfg.GlobalCfg = cloneConfig()
	cfg.GlobalCfg.GRPC = "55556"
	cfg.GlobalCfg.LogPath = "none"
	cfg.GlobalCfg.AlertThrottling = true
	cfg.GlobalCfg.MaxAlertPerSec = 3
	cfg.GlobalCfg.ThrottleSec = 30
	cfg.GlobalCfg.DefaultPostureLogs = true

	node := tp.Node{NodeName: "ubuntu-apparmor-node"}
	nodeLock := new(sync.RWMutex)

	fd := NewFeeder(&node, &nodeLock)
	if fd == nil {
		t.Fatalf("expected feeder to be created")
	}
	defer destroyFeederIfExists(fd, t)

	fd.UpdateEnforcer("AppArmor")
	containerID := "test-container-123"
	fd.ContainerNsKeyLock.Lock()
	fd.ContainerNsKey[containerID] = common.OuterKey{PidNs: 1001, MntNs: 2002}
	fd.ContainerNsKeyLock.Unlock()

	alertUID, alertCh := fd.EventStructs.AddAlertStruct("", 100)
	defer fd.EventStructs.RemoveAlertStruct(alertUID)
	logUID, logCh := fd.EventStructs.AddLogStruct("", 100)
	defer fd.EventStructs.RemoveLogStruct(logUID)

	// 1. Unmatched AppArmor / DAC failed syscalls (no KubeArmor policy) -> ContainerLog telemetry, zero alerts or AlertThreshold
	for i := 0; i < 10; i++ {
		fd.PushLog(tp.Log{
			ContainerID:              containerID,
			NamespaceName:            "default",
			PodName:                  "test-pod",
			Operation:                "File",
			Resource:                 "/etc/shadow",
			Source:                   "/usr/bin/python3",
			ProcessName:              "/usr/bin/python3",
			Result:                   "Permission denied",
			FileVisibilityEnabled:    true,
			ProcessVisibilityEnabled: true,
		})
	}

	if gotAlerts := len(alertCh); gotAlerts != 0 {
		t.Fatalf("expected 0 alerts for unmatched AppArmor telemetry, got %d", gotAlerts)
	}
	if gotLogs := len(logCh); gotLogs != 10 {
		t.Fatalf("expected 10 telemetry logs, got %d", gotLogs)
	}

	// 2. DefaultPosture events (when an Allow policy exists and non-allowed files are blocked by default posture)
	//    must NOT trigger AlertThreshold throttling.
	allowEndpoint := tp.EndPoint{
		NamespaceName: "default",
		EndPointName:  "test-pod",
		PolicyEnabled: tp.KubeArmorPolicyEnabled,
		SecurityPolicies: []tp.SecurityPolicy{
			{
				Metadata: map[string]string{
					"namespaceName": "default",
					"policyName":    "ksp-allow-app",
				},
				Spec: tp.SecuritySpec{
					Action: "Allow",
					File: tp.FileType{
						MatchPaths: []tp.FilePathType{
							{
								Path:   "/app/allowed.txt",
								Action: "Allow",
							},
						},
					},
				},
			},
		},
	}
	fd.UpdateSecurityPolicies("ADDED", allowEndpoint)

	for i := 0; i < 6; i++ {
		fd.PushLog(tp.Log{
			ContainerID:   containerID,
			NamespaceName: "default",
			PodName:       "test-pod",
			Operation:     "File",
			Resource:      "/etc/shadow",
			Source:        "/usr/bin/cat /etc/shadow",
			ProcessName:   "/usr/bin/cat",
			Result:        "Permission denied",
			PolicyEnabled: tp.KubeArmorPolicyEnabled,
		})
	}

	if gotAlerts := len(alertCh); gotAlerts != 6 {
		t.Fatalf("expected all 6 DefaultPosture events without throttling, got %d", gotAlerts)
	}
	for i := 0; i < 6; i++ {
		a := <-alertCh
		if a.Operation == "AlertThreshold" || a.Type == "SystemEvent" {
			t.Fatalf("unexpected AlertThreshold generated for DefaultPosture event %d", i)
		}
	}

	// 3. Explicit AppArmor policy violation -> first MaxAlertPerSec (3) alerts pass as MatchedPolicy,
	//    4th becomes SystemEvent (AlertThreshold) with PolicyName and Enforcer preserved, 5th+ are dropped.
	endPoint := tp.EndPoint{
		NamespaceName: "default",
		EndPointName:  "test-pod",
		PolicyEnabled: tp.KubeArmorPolicyEnabled,
		SecurityPolicies: []tp.SecurityPolicy{
			{
				Metadata: map[string]string{
					"namespaceName": "default",
					"policyName":    "ksp-block-shadow",
				},
				Spec: tp.SecuritySpec{
					Action: "Block",
					File: tp.FileType{
						MatchPaths: []tp.FilePathType{
							{
								Path:   "/etc/shadow",
								Action: "Block",
							},
						},
					},
				},
			},
		},
	}
	fd.UpdateSecurityPolicies("ADDED", endPoint)

	for i := 0; i < 6; i++ {
		fd.PushLog(tp.Log{
			ContainerID:   containerID,
			NamespaceName: "default",
			PodName:       "test-pod",
			Operation:     "File",
			Resource:      "/etc/shadow",
			Source:        "/usr/bin/cat /etc/shadow",
			ProcessName:   "/usr/bin/cat",
			Result:        "Permission denied",
			PolicyEnabled: tp.KubeArmorPolicyEnabled,
			PID:           1234,
			PPID:          1,
			UID:           1000,
		})
	}

	// Expect 3 MatchedPolicy alerts + 1 SystemEvent (AlertThreshold) = 4 total alerts (5th and 6th dropped)
	if gotAlerts := len(alertCh); gotAlerts != 4 {
		t.Fatalf("expected 4 alerts (3 MatchedPolicy + 1 AlertThreshold), got %d", gotAlerts)
	}

	for i := 0; i < 3; i++ {
		a := <-alertCh
		if a.Type != "MatchedPolicy" || a.PolicyName != "ksp-block-shadow" || a.Enforcer != "AppArmor" {
			t.Fatalf("alert %d: unexpected fields: Type=%s PolicyName=%s Enforcer=%s", i, a.Type, a.PolicyName, a.Enforcer)
		}
	}

	throttleAlert := <-alertCh
	if throttleAlert.Type != "SystemEvent" || throttleAlert.Operation != "AlertThreshold" {
		t.Fatalf("expected 4th alert to be SystemEvent/AlertThreshold, got Type=%s Operation=%s", throttleAlert.Type, throttleAlert.Operation)
	}
	if throttleAlert.PolicyName != "ksp-block-shadow" || throttleAlert.Enforcer != "AppArmor" {
		t.Fatalf("expected AlertThreshold to preserve PolicyName='ksp-block-shadow' and Enforcer='AppArmor', got PolicyName=%q Enforcer=%q", throttleAlert.PolicyName, throttleAlert.Enforcer)
	}
}
