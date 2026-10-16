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

// ListenerKind selects the transport backing a gRPC listener.
type ListenerKind int

const (
	// TCP serves gRPC over a TCP address.
	TCP ListenerKind = iota
	// UnixSocket serves gRPC over a Unix domain socket path.
	UnixSocket
)

// Profile selects a keepalive tuning preset for a gRPC server.
type Profile int

const (
	// StreamingProfile tunes keepalive for long-lived streaming RPCs.
	StreamingProfile Profile = iota
	// UnaryProfile tunes keepalive for short-lived unary RPCs.
	UnaryProfile
)

// NewListener creates a listener of the given kind bound to addr.
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

// LoadServerTLS builds mTLS server credentials for serverName using the CA
// at certPath, minting an ephemeral server certificate at startup.
func LoadServerTLS(nodeIP, certPath, certProvider, serverName string) (credentials.TransportCredentials, error) {
	serverCertConfig := cert.DefaultKubeArmorServerConfig
	serverCertConfig.DNS, serverCertConfig.IPs = cert.KubeArmorServerSANs(nodeIP, serverName, cfg.GlobalCfg.Host)
	serverCertConfig.NotAfter = time.Now().Add(365 * 24 * time.Hour)

	tlsConfig := cert.TlsConfig{
		CertCfg:      serverCertConfig,
		CertProvider: certProvider,
		CACertPath:   cert.GetCACertPath(certPath),
		CertPath:     cert.GetServerCertPath(certPath),
		NodeIP:       nodeIP,
		ServerNames:  []string{cfg.GlobalCfg.Host},
		ServerPrefix: serverName,
	}

	manager := cert.NewTlsCredentialManager(&tlsConfig)
	return manager.CreateTlsServerCredentials()
}

// KeepaliveFor returns the keepalive enforcement policy and server
// parameters for the given profile.
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
