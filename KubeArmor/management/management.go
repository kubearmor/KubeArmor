// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

// Package management owns the Management gRPC server: PolicyService,
// ProbeService, and StateAgent are registered onto it by core. This
// package has no knowledge of policy, probe, or state business logic —
// it only hosts the transport those services are registered on.
package management

import (
	"fmt"
	"net"
	"sync"

	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	"github.com/kubearmor/KubeArmor/KubeArmor/grpcutil"
	kg "github.com/kubearmor/KubeArmor/KubeArmor/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
)

// pointer to GlobalCfg used inside NewManagementServer where the cfg
// parameter shadows the cfg package import
var globalCfg = &cfg.GlobalCfg

type Config struct {
	SocketPath   string
	FallbackAddr string
	TLSEnabled   bool
	NodeIP       string
}

type ManagementServer struct {
	Listener     net.Listener
	Server       *grpc.Server
	HealthServer *health.Server
	SocketPath   string
	FallbackAddr string
	NodeIP       string
	WgServer     sync.WaitGroup
}

func NewManagementServer(cfg Config) (*ManagementServer, error) {
	if cfg.SocketPath == "" && cfg.FallbackAddr == "" {
		return nil, fmt.Errorf("either SocketPath or FallbackAddr must be set")
	}

	var listener net.Listener
	var err error

	if cfg.SocketPath != "" {
		listener, err = grpcutil.NewListener(grpcutil.UnixSocket, cfg.SocketPath)
		if err != nil {
			kg.Errf("Failed to listen on Unix socket %s: %s", cfg.SocketPath, err)
			return nil, fmt.Errorf("cannot create management listener on Unix socket %s: %s", cfg.SocketPath, err)
		}
	} else {
		listener, err = grpcutil.NewListener(grpcutil.TCP, cfg.FallbackAddr)
		if err != nil {
			return nil, fmt.Errorf("cannot create management listener on %s: %s", cfg.FallbackAddr, err)
		}
	}

	kaep, kasp := grpcutil.KeepaliveFor(grpcutil.UnaryProfile)

	var server *grpc.Server
	if cfg.TLSEnabled {
		tlsCredentials, err := grpcutil.LoadServerTLS(cfg.NodeIP, globalCfg.ManagementTLSCertPath, globalCfg.ManagementTLSCertProvider, "kubearmor-management")
		if err != nil {
			_ = listener.Close()
			return nil, fmt.Errorf("cannot load management gRPC TLS credentials: %s", err)
		}

		kg.Print("Management server started with TLS enabled")
		server = grpc.NewServer(
			grpc.Creds(tlsCredentials),
			grpc.KeepaliveEnforcementPolicy(kaep),
			grpc.KeepaliveParams(kasp),
		)
	} else {
		server = grpc.NewServer(
			grpc.KeepaliveEnforcementPolicy(kaep),
			grpc.KeepaliveParams(kasp),
		)
	}

	healthSrv := health.NewServer()
	grpc_health_v1.RegisterHealthServer(server, healthSrv)

	return &ManagementServer{
		Listener:     listener,
		Server:       server,
		HealthServer: healthSrv,
		SocketPath:   cfg.SocketPath,
		FallbackAddr: cfg.FallbackAddr,
		NodeIP:       cfg.NodeIP,
	}, nil
}

func (ms *ManagementServer) Serve() {
	ms.WgServer.Add(1)
	defer ms.WgServer.Done()

	if err := ms.Server.Serve(ms.Listener); err != nil {
		kg.Print("Terminated the management gRPC service")
	}
}

func (ms *ManagementServer) GracefulStop() {
	if ms.Server != nil {
		ms.Server.GracefulStop()
	}

	if ms.Listener != nil {
		_ = ms.Listener.Close()
		ms.Listener = nil
	}

	ms.WgServer.Wait()
}
