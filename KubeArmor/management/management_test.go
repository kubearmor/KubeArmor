// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package management

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/kubearmor/KubeArmor/KubeArmor/cert"
	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	pb "github.com/kubearmor/KubeArmor/protobuf"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
	"google.golang.org/protobuf/types/known/emptypb"
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

func freeTCPPort(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("Failed to bind test port: %v", err)
	}
	defer listener.Close()
	return strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)
}

func configureTestTLS(t *testing.T) {
	t.Helper()
	cfg.GlobalCfg.TLSCertProvider = cert.DevCertProvider
	cfg.GlobalCfg.TLSCertPath = t.TempDir()
}

func configureTestManagementPort(t *testing.T) {
	t.Helper()
	cfg.GlobalCfg.ManagementGRPC = freeTCPPort(t)
}

func setupTestServer(t *testing.T) (*ManagementServer, credentials.TransportCredentials) {
	t.Helper()
	cfg.GlobalCfg = cloneConfig()
	configureTestManagementPort(t)
	configureTestTLS(t)

	ms, err := NewManagementServer("10.0.0.1")
	if err != nil {
		t.Fatalf("Failed to create management server: %v", err)
	}

	tlsConfig := cert.TlsConfig{
		CertProvider: cert.ExternalCertProvider,
		CACertPath:   cert.GetCACertPath(cfg.GlobalCfg.TLSCertPath),
		CertPath:     cert.GetClientCertPath(cfg.GlobalCfg.TLSCertPath),
	}
	creds, err := cert.NewTlsCredentialManager(&tlsConfig).CreateTlsClientCredentials()
	if err != nil {
		t.Fatalf("Failed to create client TLS credentials: %v", err)
	}

	return ms, creds
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

func TestNewManagementServer(t *testing.T) {
	tests := []struct {
		name      string
		setup     func(t *testing.T)
		expectNil bool
	}{
		{
			name: "DefaultConfigSuccess",
			setup: func(t *testing.T) {
				cfg.GlobalCfg = cloneConfig()
				configureTestManagementPort(t)
				configureTestTLS(t)
			},
			expectNil: false,
		},
		{
			name: "PortZeroFailure",
			setup: func(t *testing.T) {
				cfg.GlobalCfg = cloneConfig()
				cfg.GlobalCfg.ManagementGRPC = "0"
			},
			expectNil: true,
		},
		{
			name: "PortInUseFailure",
			setup: func(t *testing.T) {
				cfg.GlobalCfg = cloneConfig()
				listener, err := net.Listen("tcp", ":0")
				if err != nil {
					t.Fatalf("Failed to bind test port: %v", err)
				}
				addr := listener.Addr().(*net.TCPAddr)
				cfg.GlobalCfg.ManagementGRPC = strconv.Itoa(addr.Port)
				t.Cleanup(func() { listener.Close() })
			},
			expectNil: true,
		},
		{
			name: "TLSCredentialsFailure",
			setup: func(t *testing.T) {
				cfg.GlobalCfg = cloneConfig()
				cfg.GlobalCfg.TLSEnabled = true
				configureTestManagementPort(t)
				cfg.GlobalCfg.TLSCertProvider = cert.SelfCertProvider
				cfg.GlobalCfg.TLSCertPath = t.TempDir()
			},
			expectNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup(t)

			ms, err := NewManagementServer("10.0.0.1")
			if ms != nil {
				defer func() {
					if err := ms.Destroy(); err != nil {
						t.Logf("Failed to destroy management server: %v", err)
					}
				}()
			}

			if tt.expectNil && ms != nil {
				t.Fatalf("expected management server to be nil")
			}

			if !tt.expectNil && ms == nil {
				t.Fatalf("expected management server to be created, got error: %v", err)
			}
		})
	}
}

type mockPolicyService struct {
	pb.UnimplementedPolicyServiceServer
	mu sync.Mutex
}

func (s *mockPolicyService) ContainerPolicy(ctx context.Context, in *pb.Policy) (*pb.Response, error) {
	return &pb.Response{Status: pb.PolicyStatus_Applied}, nil
}

func (s *mockPolicyService) HostPolicy(ctx context.Context, in *pb.Policy) (*pb.Response, error) {
	return &pb.Response{Status: pb.PolicyStatus_Applied}, nil
}

func (s *mockPolicyService) NetworkPolicy(ctx context.Context, in *pb.Policy) (*pb.Response, error) {
	return &pb.Response{Status: pb.PolicyStatus_Applied}, nil
}

type mockProbeService struct {
	pb.UnimplementedProbeServiceServer
}

func (s *mockProbeService) GetProbeData(ctx context.Context, _ *emptypb.Empty) (*pb.ProbeResponse, error) {
	return &pb.ProbeResponse{}, nil
}

// TestManagementServerServiceRegistration verifies PolicyService and ProbeService
// are successfully registered and respond to RPC calls.
func TestManagementServerServiceRegistration(t *testing.T) {
	ms, creds := setupTestServer(t)
	defer func() {
		if err := ms.Destroy(); err != nil {
			t.Logf("Failed to destroy management server: %v", err)
		}
	}()

	pb.RegisterPolicyServiceServer(ms.Server, &mockPolicyService{})
	pb.RegisterProbeServiceServer(ms.Server, &mockProbeService{})
	reflection.Register(ms.Server)

	go ms.Serve()
	time.Sleep(500 * time.Millisecond)

	conn, err := grpc.NewClient("localhost"+ms.Port, grpc.WithTransportCredentials(creds))
	if err != nil {
		t.Fatalf("Failed to create gRPC client: %v", err)
	}
	defer conn.Close()

	policyClient := pb.NewPolicyServiceClient(conn)
	resp, err := policyClient.ContainerPolicy(context.Background(), &pb.Policy{})
	if err != nil {
		t.Fatalf("ContainerPolicy RPC failed: %v", err)
	}
	if resp.Status != pb.PolicyStatus_Applied {
		t.Fatalf("Expected PolicyStatus_Applied, got %v", resp.Status)
	}
	t.Logf("ContainerPolicy response: Status=%v", resp.Status)

	hostResp, err := policyClient.HostPolicy(context.Background(), &pb.Policy{})
	if err != nil {
		t.Fatalf("HostPolicy RPC failed: %v", err)
	}
	if hostResp.Status != pb.PolicyStatus_Applied {
		t.Fatalf("Expected PolicyStatus_Applied, got %v", hostResp.Status)
	}
	t.Logf("HostPolicy response: Status=%v", hostResp.Status)

	netResp, err := policyClient.NetworkPolicy(context.Background(), &pb.Policy{})
	if err != nil {
		t.Fatalf("NetworkPolicy RPC failed: %v", err)
	}
	if netResp.Status != pb.PolicyStatus_Applied {
		t.Fatalf("Expected PolicyStatus_Applied, got %v", netResp.Status)
	}
	t.Logf("NetworkPolicy response: Status=%v", netResp.Status)

	probeClient := pb.NewProbeServiceClient(conn)
	probeResp, err := probeClient.GetProbeData(context.Background(), &emptypb.Empty{})
	if err != nil {
		t.Fatalf("GetProbeData RPC failed: %v", err)
	}
	if probeResp == nil {
		t.Fatalf("Expected non-nil ProbeResponse")
	}
	t.Logf("GetProbeData succeeded: ContainerList=%v", probeResp.ContainerList)
}

// TestManagementServerHealth verifies the health check service works on the management server.
func TestManagementServerHealth(t *testing.T) {
	ms, creds := setupTestServer(t)
	defer func() {
		if err := ms.Destroy(); err != nil {
			t.Logf("Failed to destroy management server: %v", err)
		}
	}()

	healthSrv := health.NewServer()
	grpc_health_v1.RegisterHealthServer(ms.Server, healthSrv)
	healthSrv.SetServingStatus("policy.PolicyService", grpc_health_v1.HealthCheckResponse_SERVING)

	go ms.Serve()
	time.Sleep(500 * time.Millisecond)

	conn, err := grpc.NewClient("localhost"+ms.Port, grpc.WithTransportCredentials(creds))
	if err != nil {
		t.Fatalf("Failed to create gRPC client: %v", err)
	}
	defer conn.Close()

	healthClient := grpc_health_v1.NewHealthClient(conn)
	resp, err := healthClient.Check(context.Background(), &grpc_health_v1.HealthCheckRequest{Service: "policy.PolicyService"})
	if err != nil {
		t.Fatalf("Health check RPC failed: %v", err)
	}
	if resp.Status != grpc_health_v1.HealthCheckResponse_SERVING {
		t.Fatalf("Expected SERVING health status, got %v", resp.Status)
	}
	t.Logf("Health check response: Status=%v", resp.Status)
}

// TestManagementServerDestroy verifies that after Destroy the server stops accepting connections.
func TestManagementServerDestroy(t *testing.T) {
	ms, creds := setupTestServer(t)

	pb.RegisterPolicyServiceServer(ms.Server, &mockPolicyService{})

	go ms.Serve()
	time.Sleep(500 * time.Millisecond)

	conn, err := grpc.NewClient("localhost"+ms.Port, grpc.WithTransportCredentials(creds))
	if err != nil {
		t.Fatalf("Failed to create gRPC client: %v", err)
	}
	defer conn.Close()

	policyClient := pb.NewPolicyServiceClient(conn)
	resp, err := policyClient.ContainerPolicy(context.Background(), &pb.Policy{})
	if err != nil {
		t.Fatalf("ContainerPolicy RPC before destroy failed: %v", err)
	}
	if resp.Status != pb.PolicyStatus_Applied {
		t.Fatalf("Expected PolicyStatus_Applied, got %v", resp.Status)
	}

	if err := ms.Destroy(); err != nil {
		t.Fatalf("Failed to destroy management server: %v", err)
	}

	_, err = policyClient.ContainerPolicy(context.Background(), &pb.Policy{})
	if err == nil {
		t.Fatal("Expected error after destroy, connection should fail")
	}
	t.Logf("Expected error after destroy: %v", err)
}
