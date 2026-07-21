// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

// Package grpcutil provides transport-only helpers shared by feeder (Observability)
// and management (Management). It contains no business logic and knows nothing
// about any specific gRPC service.
package grpcutil

import (
	"fmt"
	"net"
	"time"

	"github.com/kubearmor/KubeArmor/KubeArmor/cert"
	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
)

type ListenerKind int

const (
	TCP ListenerKind = iota
	UnixSocket
)

type Profile int

const (
	StreamingProfile Profile = iota
	UnaryProfile
)

func NewListener(kind ListenerKind, addr string) (net.Listener, error) {
	switch kind {
	case TCP:
		return net.Listen("tcp", addr)
	case UnixSocket:
		return net.Listen("unix", addr)
	default:
		return nil, fmt.Errorf("unsupported listener kind: %d", kind)
	}
}

func LoadServerTLS(nodeIP string) (credentials.TransportCredentials, error) {
	serverCertConfig := cert.DefaultKubeArmorServerConfig
	serverCertConfig.DNS, serverCertConfig.IPs = cert.KubeArmorServerSANs(nodeIP, cfg.GlobalCfg.Host)
	serverCertConfig.NotAfter = time.Now().Add(365 * 24 * time.Hour)

	tlsConfig := cert.TlsConfig{
		CertCfg:      serverCertConfig,
		CertProvider: cfg.GlobalCfg.TLSCertProvider,
		CACertPath:   cert.GetCACertPath(cfg.GlobalCfg.TLSCertPath),
		CertPath:     cert.GetServerCertPath(cfg.GlobalCfg.TLSCertPath),
		NodeIP:       nodeIP,
		ServerNames:  []string{cfg.GlobalCfg.Host},
	}

	manager := cert.NewTlsCredentialManager(&tlsConfig)
	return manager.CreateTlsServerCredentials()
}

func KeepaliveFor(p Profile) (keepalive.EnforcementPolicy, keepalive.ServerParameters) {
	switch p {
	case StreamingProfile:
		return keepalive.EnforcementPolicy{
				PermitWithoutStream: true,
			}, keepalive.ServerParameters{
				Time:    1 * time.Second,
				Timeout: 5 * time.Second,
			}
	case UnaryProfile:
		return keepalive.EnforcementPolicy{
				PermitWithoutStream: true,
			}, keepalive.ServerParameters{
				Time:    30 * time.Second,
				Timeout: 10 * time.Second,
			}
	default:
		return keepalive.EnforcementPolicy{
				PermitWithoutStream: true,
			}, keepalive.ServerParameters{
				Time:    1 * time.Second,
				Timeout: 5 * time.Second,
			}
	}
}
