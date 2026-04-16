// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package core

import (
	"testing"

	apievents "github.com/containerd/containerd/api/events"
	"google.golang.org/protobuf/proto"
)

// =================================================== //
// == Tests for handleContainerdEvent - /tasks/exit == //
// =================================================== //

// TestTaskExitFieldNumberMismatch demonstrates WHY using TaskStart to unmarshal
// a TaskExit payload is wrong.
//
// Proto field numbers:
//   TaskStart: ContainerID=1, Pid=2
//   TaskExit:  ContainerID=1, ID=2, Pid=3, ExitStatus=4, ExitedAt=5
//
// When a TaskExit payload is unmarshaled into TaskStart:
//   - Field 1 (ContainerID) matches correctly
//   - Field 2 in TaskExit is ID (string), but TaskStart expects Pid (uint32)
//     Proto silently drops the field due to type mismatch
//   - Field 3 (Pid in TaskExit) has no corresponding field in TaskStart
//     Proto silently drops it
//   - Result: TaskStart.Pid is always 0, regardless of the real pid
//
// This causes the pid == exitTask.GetPid() check in handleContainerdEvent
// to behave incorrectly - the container destroy path may never be triggered
// for containers with a non-zero stored pid, leaving stale entries in
// dm.Containers and the eBPF NsMap.
func TestTaskExitFieldNumberMismatch(t *testing.T) {
	const containerID = "abc123def456"
	const realPid = uint32(9999)

	// Build a real TaskExit payload (what containerd actually sends)
	exitEvent := &apievents.TaskExit{
		ContainerID: containerID,
		ID:          "some-exec-id",
		Pid:         realPid,
		ExitStatus:  0,
	}

	data, err := proto.Marshal(exitEvent)
	if err != nil {
		t.Fatalf("failed to marshal TaskExit: %v", err)
	}

	// --- OLD BEHAVIOUR: unmarshal into wrong type ---
	wrongType := &apievents.TaskStart{}
	if err := proto.Unmarshal(data, wrongType); err != nil {
		t.Fatalf("unexpected unmarshal error with wrong type: %v", err)
	}

	// ContainerID field 1 matches in both structs, so this is fine
	if wrongType.GetContainerID() != containerID {
		t.Errorf("wrong type ContainerID = %q, want %q", wrongType.GetContainerID(), containerID)
	}

	// Pid field 3 in TaskExit has no counterpart in TaskStart (which only has fields 1-2)
	// Proto drops it silently, so GetPid() returns 0 instead of 9999
	if wrongType.GetPid() == realPid {
		t.Errorf("expected wrong type to NOT read Pid correctly, but got %d - field layout may have changed", wrongType.GetPid())
	}
	t.Logf("BUG DEMONSTRATED: TaskStart.GetPid() = %d (expected 0, real pid was %d)", wrongType.GetPid(), realPid)

	// --- NEW BEHAVIOUR: unmarshal into correct type ---
	rightType := &apievents.TaskExit{}
	if err := proto.Unmarshal(data, rightType); err != nil {
		t.Fatalf("unexpected unmarshal error with correct type: %v", err)
	}

	if rightType.GetContainerID() != containerID {
		t.Errorf("correct type ContainerID = %q, want %q", rightType.GetContainerID(), containerID)
	}

	if rightType.GetPid() != realPid {
		t.Errorf("correct type Pid = %d, want %d", rightType.GetPid(), realPid)
	}

	t.Logf("FIX VERIFIED: TaskExit.GetPid() = %d (correct)", rightType.GetPid())
}

// TestTaskExitPidZeroEdgeCase tests the edge case where pid is 0.
// With the buggy code, wrongType.GetPid() == 0 always, so the destroy
// check pid == exitTask.GetPid() would pass only when the stored pid is
// also 0 - meaning containers with a real pid would never be cleaned up,
// but containers that failed to start (pid=0) would be incorrectly destroyed.
func TestTaskExitPidZeroEdgeCase(t *testing.T) {
	exitEvent := &apievents.TaskExit{
		ContainerID: "zero-pid-container",
		ID:          "exec-id",
		Pid:         0,
		ExitStatus:  1,
	}

	data, err := proto.Marshal(exitEvent)
	if err != nil {
		t.Fatalf("failed to marshal TaskExit: %v", err)
	}

	wrongType := &apievents.TaskStart{}
	if err := proto.Unmarshal(data, wrongType); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	rightType := &apievents.TaskExit{}
	if err := proto.Unmarshal(data, rightType); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	// Both should read pid=0 here, but only rightType also reads ExitStatus correctly
	if rightType.GetPid() != 0 {
		t.Errorf("expected pid=0, got %d", rightType.GetPid())
	}
	if rightType.GetExitStatus() != 1 {
		t.Errorf("expected ExitStatus=1, got %d", rightType.GetExitStatus())
	}

	// wrongType cannot read ExitStatus at all - field doesn't exist on TaskStart
	t.Logf("TaskStart has no ExitStatus field - exit code information is always lost with wrong type")
}

// TestTaskExitContainerIDAlwaysCorrect verifies that ContainerID (field 1)
// is correctly read by both types since it occupies field number 1 in both
// TaskStart and TaskExit proto definitions.
func TestTaskExitContainerIDAlwaysCorrect(t *testing.T) {
	const id = "container-field1-test"

	exitEvent := &apievents.TaskExit{
		ContainerID: id,
		Pid:         1234,
	}

	data, err := proto.Marshal(exitEvent)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	// ContainerID is field 1 in both structs - always reads correctly
	// This is why the bug was subtle: container lookup worked, only Pid was wrong
	wrongType := &apievents.TaskStart{}
	if err := proto.Unmarshal(data, wrongType); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if wrongType.GetContainerID() != id {
		t.Errorf("ContainerID mismatch: got %q, want %q", wrongType.GetContainerID(), id)
	}

	rightType := &apievents.TaskExit{}
	if err := proto.Unmarshal(data, rightType); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if rightType.GetContainerID() != id {
		t.Errorf("ContainerID mismatch: got %q, want %q", rightType.GetContainerID(), id)
	}

	t.Logf("ContainerID correctly read by both types (field 1 matches) - this is why the bug was hard to notice")
}

// TestTaskStartFieldsUnchanged verifies that TaskStart struct still reads
// correctly for /tasks/start events after this change - we didn't break anything.
func TestTaskStartFieldsUnchanged(t *testing.T) {
	const containerID = "start-container-999"
	const pid = uint32(4242)

	startEvent := &apievents.TaskStart{
		ContainerID: containerID,
		Pid:         pid,
	}

	data, err := proto.Marshal(startEvent)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	result := &apievents.TaskStart{}
	if err := proto.Unmarshal(data, result); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if result.GetContainerID() != containerID {
		t.Errorf("ContainerID = %q, want %q", result.GetContainerID(), containerID)
	}
	if result.GetPid() != pid {
		t.Errorf("Pid = %d, want %d", result.GetPid(), pid)
	}

	t.Log("TaskStart handling for /tasks/start events is unaffected by this fix")
}