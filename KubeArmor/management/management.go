// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package management

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/kubearmor/KubeArmor/KubeArmor/cert"
	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	kg "github.com/kubearmor/KubeArmor/KubeArmor/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/reflection"
)

type ManagementServer struct {
	Port     string
	Listener net.Listener
	Server   *grpc.Server
	NodeIP   string
	WgServer sync.WaitGroup
}

func NewManagementServer(nodeIP string) (*ManagementServer, error) {
	port := fmt.Sprintf(":%s", cfg.GlobalCfg.ManagementGRPC)

	if cfg.GlobalCfg.ManagementGRPC == "0" {
		return nil, fmt.Errorf("managementGRPC port cannot be 0")
	}

	listener, err := net.Listen("tcp", port)
	if err != nil {
		return nil, fmt.Errorf("cannot create management listener: %s", err)
	}

	server, err := createManagementGRPCServer(nodeIP)
	if err != nil {
		listener.Close()
		return nil, fmt.Errorf("cannot create management gRPC server: %s", err)
	}

	return &ManagementServer{
		Port:     port,
		Listener: listener,
		Server:   server,
		NodeIP:   nodeIP,
	}, nil
}

func (ms *ManagementServer) Serve() {
	ms.WgServer.Add(1)
	defer ms.WgServer.Done()

	if err := ms.Server.Serve(ms.Listener); err != nil {
		kg.Print("Terminated the management gRPC service")
	}
}

func (ms *ManagementServer) Destroy() error {
	if ms.Server != nil {
		ms.Server.GracefulStop()
	}

	if ms.Listener != nil {
		ms.Listener.Close()
		ms.Listener = nil
	}

	ms.WgServer.Wait()

	return nil
}

func (ms *ManagementServer) RegisterReflection() {
	reflection.Register(ms.Server)
}

func createManagementGRPCServer(nodeIP string) (*grpc.Server, error) {
	kaep := keepalive.EnforcementPolicy{
		PermitWithoutStream: true,
	}
	kasp := keepalive.ServerParameters{
		Time:    1 * time.Second,
		Timeout: 5 * time.Second,
	}

	if cfg.GlobalCfg.TLSEnabled {
		tlsCredentials, err := loadManagementTLSCredentials(nodeIP)
		if err != nil {
			return nil, err
		}

		kg.Print("Management server started with TLS enabled")

		return grpc.NewServer(
			grpc.Creds(tlsCredentials),
			grpc.KeepaliveEnforcementPolicy(kaep),
			grpc.KeepaliveParams(kasp),
		), nil
	}

	return grpc.NewServer(
		grpc.KeepaliveEnforcementPolicy(kaep),
		grpc.KeepaliveParams(kasp),
	), nil
}

func loadManagementTLSCredentials(ip string) (credentials.TransportCredentials, error) {
	serverCertConfig := cert.DefaultKubeArmorServerConfig
	serverCertConfig.DNS, serverCertConfig.IPs = cert.KubeArmorServerSANs(ip, cfg.GlobalCfg.Host)
	serverCertConfig.NotAfter = time.Now().Add(365 * 24 * time.Hour)

	tlsConfig := cert.TlsConfig{
		CertCfg:      serverCertConfig,
		CertProvider: cfg.GlobalCfg.TLSCertProvider,
		CACertPath:   cert.GetCACertPath(cfg.GlobalCfg.TLSCertPath),
		CertPath:     cert.GetServerCertPath(cfg.GlobalCfg.TLSCertPath),
		NodeIP:       ip,
		ServerNames:  []string{cfg.GlobalCfg.Host},
	}

	manager := cert.NewTlsCredentialManager(&tlsConfig)
	return manager.CreateTlsServerCredentials()
}
