// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package feeder

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"testing"

	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
	pb "github.com/kubearmor/KubeArmor/protobuf"
)

var baseCfg cfg.KubearmorConfig

func cloneConfig() cfg.KubearmorConfig {
	c := baseCfg

	if baseCfg.ConfigUntrackedNs != nil {
		c.ConfigUntrackedNs = make([]string, len(baseCfg.ConfigUntrackedNs))
		copy(c.ConfigUntrackedNs, baseCfg.ConfigUntrackedNs)
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
