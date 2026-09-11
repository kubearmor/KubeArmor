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
	"time"

	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
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

// ================== //
// == NewFeeder ==    //
// ================== //

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
				// a directory path cannot be opened as a writable file
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

// Two goroutines simultaneously adding entries must not race.
func TestEventStructs_ConcurrentAdd(t *testing.T) {
	es := &EventStructs{
		MsgStructs:   make(map[string]EventStruct[pb.Message]),
		AlertStructs: make(map[string]EventStruct[pb.Alert]),
		LogStructs:   make(map[string]EventStruct[pb.Log]),
	}

	const workers = 20
	var wg sync.WaitGroup
	wg.Add(workers)

	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			es.AddMsgStruct("filter", 1)
		}()
	}

	wg.Wait()

	es.MsgLock.RLock()
	got := len(es.MsgStructs)
	es.MsgLock.RUnlock()

	if got != workers {
		t.Fatalf("expected %d entries, got %d", workers, got)
	}
}

// UIDs returned by AddXxxStruct must be unique across repeated calls.
func TestEventStructs_UniqueUIDs(t *testing.T) {
	es := &EventStructs{
		MsgStructs:   make(map[string]EventStruct[pb.Message]),
		AlertStructs: make(map[string]EventStruct[pb.Alert]),
		LogStructs:   make(map[string]EventStruct[pb.Log]),
	}

	seen := make(map[string]struct{})
	for i := 0; i < 50; i++ {
		uid, _ := es.AddMsgStruct("f", 1)
		if _, dup := seen[uid]; dup {
			t.Fatalf("duplicate uid returned: %s", uid)
		}
		seen[uid] = struct{}{}
	}
}

// Removing a uid that was never added must not panic.
func TestEventStructs_RemoveNonExistent(t *testing.T) {
	es := &EventStructs{
		MsgStructs:   make(map[string]EventStruct[pb.Message]),
		AlertStructs: make(map[string]EventStruct[pb.Alert]),
		LogStructs:   make(map[string]EventStruct[pb.Log]),
	}

	es.RemoveMsgStruct("ghost-uid")
	es.RemoveAlertStruct("ghost-uid")
	es.RemoveLogStruct("ghost-uid")
}

func TestParseDataString(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  map[string]string
	}{
		{
			name:  "EmptyString",
			input: "",
			want:  nil,
		},
		{
			name:  "SinglePair",
			input: "syscall=SYS_EXECVE",
			want:  map[string]string{"Syscall": "SYS_EXECVE"},
		},
		{
			name:  "MultiplePairs",
			input: "syscall=SYS_OPEN fd=3 flags=O_RDONLY",
			want: map[string]string{
				"Syscall": "SYS_OPEN",
				"Fd":      "3",
				"Flags":   "O_RDONLY",
			},
		},
		{
			name:  "ValueContainsEquals",
			input: "expr=a=b",
			want:  map[string]string{"Expr": "a=b"},
		},
		{
			name:  "KeyCapitalized",
			input: "path=/etc/passwd",
			want:  map[string]string{"Path": "/etc/passwd"},
		},
		{
			name:  "PairWithNoEquals",
			input: "noequals syscall=SYS_READ",
			want:  map[string]string{"Syscall": "SYS_READ"},
		},
		{
			name:  "LeadingAndTrailingSpaces",
			input: "  syscall=SYS_WRITE  ",
			want:  map[string]string{"Syscall": "SYS_WRITE"},
		},
		{
			name:  "EmptyValue",
			input: "key=",
			want:  map[string]string{"Key": ""},
		},
		{
			name:  "SingleCharKey",
			input: "a=1",
			want:  map[string]string{"A": "1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseDataString(tt.input)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseDataString(%q)\n  got  %v\n  want %v", tt.input, got, tt.want)
			}
		})
	}
}

// ========================= //
// == MarshalVisibilityLog== //
// ========================= //

func TestMarshalVisibilityLog(t *testing.T) {
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
		orig := cfg.GlobalCfg.DropResourceFromProcessLogs
		defer func() { cfg.GlobalCfg.DropResourceFromProcessLogs = orig }()
		cfg.GlobalCfg.DropResourceFromProcessLogs = false

		got := MarshalVisibilityLog(visibilityLog)
		if !reflect.DeepEqual(got, expectedMarshaledLog) {
			t.Errorf("[FAIL] expected %+v\ngot     %+v", expectedMarshaledLog, got)
		}
	})

	t.Run("WithoutResource", func(t *testing.T) {
		orig := cfg.GlobalCfg.DropResourceFromProcessLogs
		defer func() { cfg.GlobalCfg.DropResourceFromProcessLogs = orig }()
		cfg.GlobalCfg.DropResourceFromProcessLogs = true

		want := &pb.Log{}
		*want = *expectedMarshaledLog
		want.Resource = ""

		got := MarshalVisibilityLog(visibilityLog)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("[FAIL] expected %+v\ngot     %+v", want, got)
		}
	})

	t.Run("WithOwner", func(t *testing.T) {
		orig := cfg.GlobalCfg.DropResourceFromProcessLogs
		defer func() { cfg.GlobalCfg.DropResourceFromProcessLogs = orig }()
		cfg.GlobalCfg.DropResourceFromProcessLogs = false

		logWithOwner := visibilityLog
		logWithOwner.Owner = &tp.PodOwner{
			Ref:       "Deployment",
			Name:      "nginx",
			Namespace: "default",
		}

		got := MarshalVisibilityLog(logWithOwner)
		if got.Owner == nil {
			t.Fatal("expected Owner to be set, got nil")
		}
		if got.Owner.Ref != "Deployment" || got.Owner.Name != "nginx" || got.Owner.Namespace != "default" {
			t.Errorf("Owner mismatch: got %+v", got.Owner)
		}
	})

	t.Run("WithEmptyOwner", func(t *testing.T) {
		logWithEmptyOwner := visibilityLog
		logWithEmptyOwner.Owner = &tp.PodOwner{}

		got := MarshalVisibilityLog(logWithEmptyOwner)
		if got.Owner != nil {
			t.Errorf("expected Owner to be nil for empty PodOwner, got %+v", got.Owner)
		}
	})

	t.Run("WithEventData", func(t *testing.T) {
		logWithEventData := visibilityLog
		logWithEventData.EventData = map[string]string{"Syscall": "SYS_OPEN"}

		got := MarshalVisibilityLog(logWithEventData)
		if got.EventData == nil {
			t.Fatal("expected EventData to be non-nil")
		}
		if got.EventData["Syscall"] != "SYS_OPEN" {
			t.Errorf("EventData mismatch: got %v", got.EventData)
		}
	})

	t.Run("WithNonUTF8Resource", func(t *testing.T) {
		orig := cfg.GlobalCfg.DropResourceFromProcessLogs
		defer func() { cfg.GlobalCfg.DropResourceFromProcessLogs = orig }()
		cfg.GlobalCfg.DropResourceFromProcessLogs = false

		logWithBadResource := visibilityLog
		logWithBadResource.Resource = "bad\x80bytes"

		got := MarshalVisibilityLog(logWithBadResource)
		for _, r := range got.Resource {
			if r == '\uFFFD' {
				// replacement character present -- fine, the field was sanitised
				return
			}
		}
		// no replacement character is also acceptable as long as it didn't panic
	})
}

// =============================== //
// == ShouldDropAlertsPerContainer //
// =============================== //

func newTestFeeder() *Feeder {
	fd := &Feeder{}
	fd.AlertMap = make(map[OuterKey]AlertThrottleState)
	return fd
}

func TestShouldDropAlertsPerContainer_FirstEvent(t *testing.T) {
	cfg.GlobalCfg.MaxAlertPerSec = 10
	cfg.GlobalCfg.ThrottleSec = 5

	fd := newTestFeeder()
	alert, throttle := fd.ShouldDropAlertsPerContainer(1, 2)

	if alert || throttle {
		t.Fatalf("first event should not be dropped: alert=%v throttle=%v", alert, throttle)
	}
}

func TestShouldDropAlertsPerContainer_BelowThreshold(t *testing.T) {
	cfg.GlobalCfg.MaxAlertPerSec = 10
	cfg.GlobalCfg.ThrottleSec = 5

	fd := newTestFeeder()

	for i := 0; i < 5; i++ {
		alert, throttle := fd.ShouldDropAlertsPerContainer(1, 2)
		if alert || throttle {
			t.Fatalf("event %d should not be dropped below threshold", i+1)
		}
	}
}

func TestShouldDropAlertsPerContainer_ExceedsThreshold(t *testing.T) {
	cfg.GlobalCfg.MaxAlertPerSec = 3
	cfg.GlobalCfg.ThrottleSec = 5

	fd := newTestFeeder()

	var alertRaised bool
	for i := 0; i < 10; i++ {
		alert, _ := fd.ShouldDropAlertsPerContainer(1, 2)
		if alert {
			alertRaised = true
			break
		}
	}

	if !alertRaised {
		t.Fatal("expected throttle alert after exceeding max alerts per second")
	}
}

func TestShouldDropAlertsPerContainer_ThrottleStateActive(t *testing.T) {
	cfg.GlobalCfg.MaxAlertPerSec = 1
	cfg.GlobalCfg.ThrottleSec = 60

	fd := newTestFeeder()

	// exhaust the limit
	for i := 0; i < 5; i++ {
		fd.ShouldDropAlertsPerContainer(10, 20)
	}

	alert, throttle := fd.ShouldDropAlertsPerContainer(10, 20)
	if !alert {
		t.Fatal("expected alert=true when throttle state is active")
	}
	if !throttle {
		t.Fatal("expected throttle=true when throttle state is active")
	}
}

func TestShouldDropAlertsPerContainer_NilAlertMapInitialized(t *testing.T) {
	cfg.GlobalCfg.MaxAlertPerSec = 10
	cfg.GlobalCfg.ThrottleSec = 5

	// AlertMap intentionally left nil to test lazy initialisation
	fd := &Feeder{}

	alert, throttle := fd.ShouldDropAlertsPerContainer(5, 6)
	if alert || throttle {
		t.Fatalf("nil AlertMap: first event must not be dropped, got alert=%v throttle=%v", alert, throttle)
	}
	if fd.AlertMap == nil {
		t.Fatal("AlertMap was not initialised")
	}
}

func TestShouldDropAlertsPerContainer_IsolatedPerKey(t *testing.T) {
	cfg.GlobalCfg.MaxAlertPerSec = 2
	cfg.GlobalCfg.ThrottleSec = 5

	fd := newTestFeeder()

	// saturate key (1,2)
	for i := 0; i < 10; i++ {
		fd.ShouldDropAlertsPerContainer(1, 2)
	}

	// key (3,4) should be independent
	alert, throttle := fd.ShouldDropAlertsPerContainer(3, 4)
	if alert || throttle {
		t.Fatalf("separate container key must not be throttled, got alert=%v throttle=%v", alert, throttle)
	}
}

// ========================= //
// == DeleteAlertMapKey ==   //
// ========================= //

func TestDeleteAlertMapKey(t *testing.T) {
	fd := newTestFeeder()

	key := OuterKey{PidNs: 100, MntNs: 200}
	fd.AlertMap[key] = AlertThrottleState{EventCount: 5}

	fd.DeleteAlertMapKey(kl_OuterKey(100, 200))

	if _, exists := fd.AlertMap[key]; exists {
		t.Fatal("expected key to be deleted from AlertMap")
	}
}

func TestDeleteAlertMapKey_NonExistent(t *testing.T) {
	fd := newTestFeeder()
	// should not panic when key is absent
	fd.DeleteAlertMapKey(kl_OuterKey(99, 99))
}

// kl_OuterKey is a small helper so the test file doesn't import the common
// package solely for this construction.
func kl_OuterKey(pid, mnt uint32) kl.OuterKey {
	return kl.OuterKey{PidNs: pid, MntNs: mnt}
}

// ========================= //
// == UpdateEnforcer ==      //
// ========================= //

func TestUpdateEnforcer(t *testing.T) {
	tests := []struct {
		name     string
		enforcer string
		want     string
	}{
		{"SetBPFLSM", "BPFLSM", "BPFLSM"},
		{"SetAppArmor", "AppArmor", "AppArmor"},
		{"SetEmpty", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fd := &Feeder{}
			fd.EnforcerLock = new(sync.RWMutex)
			fd.Enforcer = "eBPF Monitor"

			fd.UpdateEnforcer(tt.enforcer)

			if got := fd.GetEnforcer(); got != tt.want {
				t.Errorf("GetEnforcer() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestUpdateEnforcer_Concurrent(t *testing.T) {
	fd := &Feeder{}
	fd.EnforcerLock = new(sync.RWMutex)
	fd.Enforcer = "eBPF Monitor"

	const workers = 50
	var wg sync.WaitGroup
	wg.Add(workers * 2)

	for i := 0; i < workers; i++ {
		go func(i int) {
			defer wg.Done()
			if i%2 == 0 {
				fd.UpdateEnforcer("BPFLSM")
			} else {
				fd.UpdateEnforcer("AppArmor")
			}
		}(i)
		go func() {
			defer wg.Done()
			_ = fd.GetEnforcer()
		}()
	}

	wg.Wait()
	// the test succeeds if it does not race (run with -race)
}

// ========================= //
// == UserNameMap ==         //
// ========================= //

func TestUserNameMap_CacheHit(t *testing.T) {
	m := UserNameMap{
		usernames: make(map[uint32]cachedUserName),
		ttl:       10 * time.Minute,
	}

	// seed the cache directly
	m.usernames[0] = cachedUserName{
		Username:  "root",
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}

	got := m.GetUsername(0)
	if got != "root" {
		t.Errorf("expected cached username 'root', got %q", got)
	}
}

func TestUserNameMap_CacheExpiry(t *testing.T) {
	m := UserNameMap{
		usernames: make(map[uint32]cachedUserName),
		ttl:       1 * time.Millisecond,
	}

	// plant an already-expired entry for an unknown uid
	m.usernames[99999] = cachedUserName{
		Username:  "stale",
		ExpiresAt: time.Now().Add(-time.Second),
	}

	// After expiry the entry should be refreshed. UID 99999 is unlikely to
	// exist on the test host so we expect an empty string back (not "stale").
	got := m.GetUsername(99999)
	if got == "stale" {
		t.Errorf("expected stale cache entry to be refreshed, still got 'stale'")
	}
}

func TestUserNameMap_UnknownUID(t *testing.T) {
	m := UserNameMap{
		usernames: make(map[uint32]cachedUserName),
		ttl:       10 * time.Minute,
	}

	// UID 999999 is almost certainly not on any CI host
	got := m.GetUsername(999999)
	if got != "" {
		t.Errorf("expected empty string for unknown uid, got %q", got)
	}
}

func TestUserNameMap_ConcurrentAccess(t *testing.T) {
	m := UserNameMap{
		usernames: make(map[uint32]cachedUserName),
		ttl:       10 * time.Minute,
	}

	const workers = 30
	var wg sync.WaitGroup
	wg.Add(workers)

	for i := 0; i < workers; i++ {
		go func(i int) {
			defer wg.Done()
			_ = m.GetUsername(uint32(i % 5))
		}(i)
	}

	wg.Wait()
	// passes if -race finds no issues
}
