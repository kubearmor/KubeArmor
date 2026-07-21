// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package management

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/kubearmor/KubeArmor/KubeArmor/cert"
	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	pb "github.com/kubearmor/KubeArmor/protobuf"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
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

func configureTestTLS(t *testing.T) {
	t.Helper()
	cfg.GlobalCfg.TLSCertProvider = cert.DevCertProvider
	cfg.GlobalCfg.TLSCertPath = t.TempDir()
}

func serverAddr(t *testing.T, s *ManagementServer) string {
	t.Helper()
	port := s.Listener.Addr().(*net.TCPAddr).Port
	return fmt.Sprintf("127.0.0.1:%d", port)
}

func createClientCreds(t *testing.T) credentials.TransportCredentials {
	t.Helper()
	tlsConfig := cert.TlsConfig{
		CertProvider: cert.ExternalCertProvider,
		CACertPath:   cert.GetCACertPath(cfg.GlobalCfg.TLSCertPath),
		CertPath:     cert.GetClientCertPath(cfg.GlobalCfg.TLSCertPath),
	}
	creds, err := cert.NewTlsCredentialManager(&tlsConfig).CreateTlsClientCredentials()
	if err != nil {
		t.Fatalf("Failed to create client TLS credentials: %v", err)
	}
	return creds
}

func setupTestServer(t *testing.T) (*ManagementServer, credentials.TransportCredentials) {
	t.Helper()
	cfg.GlobalCfg = cloneConfig()
	configureTestTLS(t)

	ms, err := NewManagementServer(Config{
		Addr:       ":0",
		TLSEnabled: cfg.GlobalCfg.TLSEnabled,
		NodeIP:     "10.0.0.1",
	})
	if err != nil {
		t.Fatalf("Failed to create management server: %v", err)
	}

	return ms, createClientCreds(t)
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

func TestNewServer(t *testing.T) {
	tests := []struct {
		name      string
		cfg       Config
		expectNil bool
	}{
		{
			name: "DefaultConfigSuccess",
			cfg: Config{
				Addr:       ":0",
				TLSEnabled: true,
				NodeIP:     "10.0.0.1",
			},
			expectNil: false,
		},
		{
			name: "BothAddrAndSocketPathEmptyFailure",
			cfg: Config{
				TLSEnabled: false,
				NodeIP:     "10.0.0.1",
			},
			expectNil: true,
		},
		{
			name: "TLSCredentialsFailure",
			cfg: Config{
				Addr:       ":0",
				TLSEnabled: true,
				NodeIP:     "10.0.0.1",
			},
			expectNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg.GlobalCfg = cloneConfig()

			if tt.cfg.TLSEnabled && tt.name != "TLSCredentialsFailure" {
				configureTestTLS(t)
			}

			if tt.name == "TLSCredentialsFailure" {
				cfg.GlobalCfg.TLSEnabled = true
				cfg.GlobalCfg.TLSCertProvider = cert.SelfCertProvider
				cfg.GlobalCfg.TLSCertPath = t.TempDir()
			}

			ms, err := NewManagementServer(tt.cfg)
			if ms != nil {
				defer ms.GracefulStop()
			}

			if tt.expectNil && ms != nil {
				t.Fatalf("expected server to be nil")
			}

			if !tt.expectNil && ms == nil {
				t.Fatalf("expected server to be created, got error: %v", err)
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

// TestServiceRegistration verifies PolicyService and ProbeService
// are successfully registered and respond to RPC calls.
func TestServiceRegistration(t *testing.T) {
	ms, creds := setupTestServer(t)
	defer ms.GracefulStop()

	pb.RegisterPolicyServiceServer(ms.Server, &mockPolicyService{})
	pb.RegisterProbeServiceServer(ms.Server, &mockProbeService{})
	reflection.Register(ms.Server)

	go ms.Serve()
	time.Sleep(500 * time.Millisecond)

	addr := serverAddr(t, ms)
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(creds))
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

// TestHealth verifies the embedded health check service works on the management server.
func TestHealth(t *testing.T) {
	ms, creds := setupTestServer(t)
	defer ms.GracefulStop()

	ms.HealthServer.SetServingStatus("policy.PolicyService", grpc_health_v1.HealthCheckResponse_SERVING)

	go ms.Serve()
	time.Sleep(500 * time.Millisecond)

	addr := serverAddr(t, ms)
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(creds))
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

// TestGracefulStop verifies that after GracefulStop the server stops accepting connections.
func TestGracefulStop(t *testing.T) {
	ms, creds := setupTestServer(t)

	pb.RegisterPolicyServiceServer(ms.Server, &mockPolicyService{})

	go ms.Serve()
	time.Sleep(500 * time.Millisecond)

	addr := serverAddr(t, ms)
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(creds))
	if err != nil {
		t.Fatalf("Failed to create gRPC client: %v", err)
	}
	defer conn.Close()

	policyClient := pb.NewPolicyServiceClient(conn)
	resp, err := policyClient.ContainerPolicy(context.Background(), &pb.Policy{})
	if err != nil {
		t.Fatalf("ContainerPolicy RPC before stop failed: %v", err)
	}
	if resp.Status != pb.PolicyStatus_Applied {
		t.Fatalf("Expected PolicyStatus_Applied, got %v", resp.Status)
	}

	ms.GracefulStop()

	_, err = policyClient.ContainerPolicy(context.Background(), &pb.Policy{})
	if err == nil {
		t.Fatal("Expected error after GracefulStop, connection should fail")
	}
	t.Logf("Expected error after GracefulStop: %v", err)
}
