// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

// Package server exports kubearmor logs
package server

import (
	"time"

	"github.com/kubearmor/KubeArmor/KubeArmor/cert"
	cfg "github.com/kubearmor/KubeArmor/pkg/KubeArmorRelayServer/config"
	"google.golang.org/grpc/credentials"
)

func loadTLSClientCredentials() (credentials.TransportCredentials, error) {
	var clientCertConfig cert.CertConfig
	// create certificate configuration
	if cfg.GlobalConfig.TLSCertProvider == cfg.SelfCertProvider {
		clientCertConfig = cert.DefaultKubeArmorClientConfig
		clientCertConfig.NotAfter = time.Now().AddDate(1, 0, 0) // valid for 1 year
	}
	// create tls credential configuration
	tlsConfig := cert.TlsConfig{
		CertCfg:      clientCertConfig,
		CertProvider: cfg.GlobalConfig.TLSCertProvider,
		CACertPath:   cert.GetCACertPath(cfg.GlobalConfig.TLSCertPath),
		CertPath:     cert.GetClientCertPath(cfg.GlobalConfig.TLSCertPath),
	}
	creds, err := cert.NewTlsCredentialManager(&tlsConfig).CreateTlsClientCredentials()
	return creds, err
}

func loadTLSServerCredentials() (credentials.TransportCredentials, error) {
	var serverCertConfig cert.CertConfig
	if cfg.GlobalConfig.TLSCertProvider == cfg.SelfCertProvider {
		// create certificate configuration
		serverCertConfig = cert.DefaultKubeArmorServerConfig
		serverCertConfig.NotAfter = time.Now().AddDate(1, 0, 0) // valid for 1 year
	}
	// create tls credential configuration
	tlsConfig := cert.TlsConfig{
		CertCfg:      serverCertConfig,
		CertProvider: cfg.GlobalConfig.TLSCertProvider,
		CACertPath:   cert.GetCACertPath(cfg.GlobalConfig.TLSCertPath),
		CertPath:     cert.GetServerCertPath(cfg.GlobalConfig.TLSCertPath),
	}
	creds, err := cert.NewTlsCredentialManager(&tlsConfig).CreateTlsServerCredentials()
	return creds, err
}
