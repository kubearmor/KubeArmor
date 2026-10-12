// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package core

import (
	"context"
	"testing"

	"github.com/kubearmor/KubeArmor/KubeArmor/management"
	pb "github.com/kubearmor/KubeArmor/protobuf"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
)

func TestSetHealthStatus(t *testing.T) {
	tests := []struct {
		serviceName string
		management  bool
	}{
		{pb.PolicyService_ServiceDesc.ServiceName, true},
		{pb.ProbeService_ServiceDesc.ServiceName, true},
		{pb.StateAgent_ServiceDesc.ServiceName, true},
		{pb.LogService_ServiceDesc.ServiceName, false},
	}

	for _, tt := range tests {
		t.Run(tt.serviceName, func(t *testing.T) {
			dm := &KubeArmorDaemon{
				GRPCHealthServer: health.NewServer(),
				ManagementServer: &management.ManagementServer{HealthServer: health.NewServer()},
			}
			request := &grpc_health_v1.HealthCheckRequest{Service: tt.serviceName}

			for _, want := range []grpc_health_v1.HealthCheckResponse_ServingStatus{
				grpc_health_v1.HealthCheckResponse_SERVING,
				grpc_health_v1.HealthCheckResponse_NOT_SERVING,
			} {
				if err := dm.SetHealthStatus(tt.serviceName, want); err != nil {
					t.Fatalf("SetHealthStatus: %v", err)
				}

				response, err := dm.GRPCHealthServer.Check(context.Background(), request)
				if err != nil {
					t.Fatalf("dedicated health check: %v", err)
				}
				if response.Status != want {
					t.Errorf("dedicated health status = %v, want %v", response.Status, want)
				}

				response, err = dm.ManagementServer.HealthServer.Check(context.Background(), request)
				if !tt.management {
					if status.Code(err) != codes.NotFound {
						t.Errorf("management health check for LogService = %v, want NotFound", err)
					}
					continue
				}
				if err != nil {
					t.Fatalf("management health check: %v", err)
				}
				if response.Status != want {
					t.Errorf("management health status = %v, want %v", response.Status, want)
				}
			}
		})
	}
}

func TestSetHealthStatusWithSingleEndpoint(t *testing.T) {
	tests := []struct {
		name        string
		serviceName string
		management  bool
	}{
		{"Kubernetes log health", pb.LogService_ServiceDesc.ServiceName, false},
		{"dedicated policy health", pb.PolicyService_ServiceDesc.ServiceName, false},
		{"management policy health", pb.PolicyService_ServiceDesc.ServiceName, true},
		{"management probe health", pb.ProbeService_ServiceDesc.ServiceName, true},
		{"management state health", pb.StateAgent_ServiceDesc.ServiceName, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			healthServer := health.NewServer()
			dm := &KubeArmorDaemon{}
			if tt.management {
				dm.ManagementServer = &management.ManagementServer{HealthServer: healthServer}
			} else {
				dm.GRPCHealthServer = healthServer
			}

			if err := dm.SetHealthStatus(tt.serviceName, grpc_health_v1.HealthCheckResponse_SERVING); err != nil {
				t.Fatalf("SetHealthStatus: %v", err)
			}
			response, err := healthServer.Check(context.Background(), &grpc_health_v1.HealthCheckRequest{Service: tt.serviceName})
			if err != nil {
				t.Fatalf("health check: %v", err)
			}
			if response.Status != grpc_health_v1.HealthCheckResponse_SERVING {
				t.Errorf("health status = %v, want SERVING", response.Status)
			}
		})
	}
}

func TestSetHealthStatusWithoutMatchingEndpoint(t *testing.T) {
	tests := []struct {
		name        string
		serviceName string
		management  *management.ManagementServer
	}{
		{"no health servers", pb.PolicyService_ServiceDesc.ServiceName, nil},
		{"uninitialized management health", pb.PolicyService_ServiceDesc.ServiceName, &management.ManagementServer{}},
		{"log health without dedicated endpoint", pb.LogService_ServiceDesc.ServiceName, &management.ManagementServer{HealthServer: health.NewServer()}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dm := &KubeArmorDaemon{ManagementServer: tt.management}
			if err := dm.SetHealthStatus(tt.serviceName, grpc_health_v1.HealthCheckResponse_SERVING); err == nil {
				t.Fatal("expected an error when no matching health endpoint is initialized")
			}
		})
	}
}
