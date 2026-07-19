// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package feeder

import (
	"net"
	"testing"

	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
	"go.opentelemetry.io/otel/log"
	"google.golang.org/grpc"
)

func TestMapSeverity(t *testing.T) {
	tests := []struct {
		severity string
		expected log.Severity
	}{
		{"critical", log.SeverityFatal},
		{"10", log.SeverityFatal},
		{"9", log.SeverityFatal},
		{"high", log.SeverityError},
		{"8", log.SeverityError},
		{"medium", log.SeverityWarn},
		{"5", log.SeverityWarn},
		{"low", log.SeverityInfo},
		{"1", log.SeverityInfo},
		{"unknown", log.SeverityInfo},
	}

	for _, tt := range tests {
		got := mapSeverity(tt.severity)
		if got != tt.expected {
			t.Errorf("mapSeverity(%q) = %v; want %v", tt.severity, got, tt.expected)
		}
	}
}

func TestMapMessageLevel(t *testing.T) {
	tests := []struct {
		level    string
		expected log.Severity
	}{
		{"DEBUG", log.SeverityDebug},
		{"INFO", log.SeverityInfo},
		{"WARN", log.SeverityWarn},
		{"WARNING", log.SeverityWarn},
		{"ERROR", log.SeverityError},
		{"unknown", log.SeverityInfo},
	}

	for _, tt := range tests {
		got := mapMessageLevel(tt.level)
		if got != tt.expected {
			t.Errorf("mapMessageLevel(%q) = %v; want %v", tt.level, got, tt.expected)
		}
	}
}

func TestNewOTelExporterAndPush(t *testing.T) {
	// Start a dummy gRPC server to avoid connection timeouts
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer lis.Close()

	s := grpc.NewServer()
	go func() {
		_ = s.Serve(lis)
	}()
	defer s.Stop()

	exporter, err := NewOTelExporter(lis.Addr().String(), true)
	if err != nil {
		t.Fatalf("Failed to initialize OTel exporter: %v", err)
	}
	defer exporter.Shutdown()

	// Verify PushLog does not panic
	logData := tp.Log{
		ClusterName:       "test-cluster",
		NamespaceName:     "test-ns",
		PodName:           "test-pod",
		ContainerName:     "test-container",
		ContainerID:       "test-container-id",
		ContainerImage:    "test-image",
		HostName:          "test-host",
		NodeID:            "test-node",
		PID:               1234,
		PPID:              123,
		ProcessName:       "test-process",
		ParentProcessName: "parent-process",
		UserName:          "root",
		UID:               0,
		Severity:          "high",
		Message:           "Security alert",
		Type:              "MatchedPolicy",
		Operation:         "Process",
		Enforcer:          "BPFLSM",
		PolicyName:        "block-process",
		Source:            "source",
		Resource:          "resource",
		Cwd:               "/",
		Data:              "data",
		EventData:         map[string]string{"foo": "bar"},
	}

	// This should run and log/emit to the batch processor without panicking
	exporter.PushLog(logData)

	// Verify PushMessage does not panic
	exporter.PushMessage("INFO", "KubeArmor started successfully")
}
