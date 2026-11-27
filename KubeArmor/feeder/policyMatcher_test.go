// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package feeder

import (
	"sync"
	"testing"

	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

// Process exit events are telemetry only: a process rule must alert on the exec,
// but not again when the same process exits.
func TestUpdateMatchedPolicySkipsProcessExit(t *testing.T) {
	cfg.GlobalCfg = cloneConfig()
	cfg.GlobalCfg.GRPC = "55557"
	cfg.GlobalCfg.LogPath = "none"
	cfg.GlobalCfg.HostPolicy = true
	cfg.GlobalCfg.Host = "exit-test-node"

	node := tp.Node{
		NodeName:                 "exit-test-node",
		PolicyEnabled:            tp.KubeArmorPolicyEnabled,
		ProcessVisibilityEnabled: true,
	}
	nodeLock := new(sync.RWMutex)

	fd := NewFeeder(&node, &nodeLock)
	if fd == nil {
		t.Fatalf("expected feeder to be created")
	}
	defer destroyFeederIfExists(fd, t)

	fd.UpdateHostSecurityPolicies("ADDED", []tp.HostSecurityPolicy{{
		Metadata: map[string]string{"policyName": "audit-sleep"},
		Spec: tp.HostSecuritySpec{
			Process: tp.ProcessType{
				MatchPaths: []tp.ProcessPathType{{Path: "/usr/bin/sleep", Action: "Audit"}},
			},
		},
	}})

	base := tp.Log{
		Operation:   "Process",
		ProcessName: "/usr/bin/sleep",
		Source:      "/usr/bin/bash",
		Result:      "Passed",
	}

	exec := base
	exec.Resource = "/usr/bin/sleep 1"
	exec.Data = "syscall=SYS_EXECVE"
	if got := fd.UpdateMatchedPolicy(exec); got.Type != "MatchedHostPolicy" || got.PolicyName != "audit-sleep" {
		t.Fatalf("exec: expected MatchedHostPolicy from audit-sleep, got type=%q policy=%q", got.Type, got.PolicyName)
	}

	exit := base
	exit.Resource = "/usr/bin/sleep"
	exit.Data = tp.ProcessExitDataPrefix + " exitCode=0 signal=0"
	if !tp.IsProcessExitLog(exit) {
		t.Fatalf("expected the exit log to be recognised as a process exit")
	}
	got := fd.UpdateMatchedPolicy(exit)
	if got.Type != "HostLog" || got.PolicyName != "" {
		t.Fatalf("exit: expected HostLog telemetry without a policy, got type=%q policy=%q", got.Type, got.PolicyName)
	}
}
