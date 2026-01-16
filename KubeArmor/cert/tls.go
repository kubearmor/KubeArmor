// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

// Package cert is responsible for generating certs dynamically and loading the certs from external sources.
package cert

import (
	"crypto/tls"

	"google.golang.org/grpc/credentials"
	"k8s.io/client-go/kubernetes"
)

const (
	SelfCertProvider     string = "self"
	ExternalCertProvider string = "external"
)

type TlsConfig struct {
	// Server/Client Certificate Configurations
	CertCfg CertConfig
	// If CA is Provided Using a K8s Secret
	// Namespace, Secret and K8sClient are Required
	ReadCACertFromSecret bool
	Secret               string
	Namespace            string
	K8sClient            *kubernetes.Clientset

	CACertPath CertPath
	CertPath   CertPath
	// Source of Client/Server Certificate,
	// "self" : Certificates Will be Generated Dynamically
	// "external": Certificates Are Provided Using File
	CertProvider string
}

type TlsCredentialManager struct {
	CertLoader CertLoader
}

func NewTlsCredentialManager(cfg *TlsConfig) *TlsCredentialManager {
	switch cfg.CertProvider {
	case SelfCertProvider:
		if cfg.ReadCACertFromSecret {
			cl := K8sCertLoader{
				CertConfig: cfg.CertCfg,
				K8sClient:  cfg.K8sClient,
				Namespace:  cfg.Namespace,
				Secret:     cfg.Secret,
			}
			return &TlsCredentialManager{
				CertLoader: &cl,
			}
		}
		cl := SelfSignedCertLoader{
			CaCertPath: cfg.CACertPath,
			CertConfig: cfg.CertCfg,
		}
		return &TlsCredentialManager{
			CertLoader: &cl,
		}
	case ExternalCertProvider:
		cl := ExternalCertLoader{
			CaCertPath: cfg.CACertPath,
			CertPath:   cfg.CertPath,
		}
		return &TlsCredentialManager{
			CertLoader: &cl,
		}
	}
	return nil
}

func (manager *TlsCredentialManager) CreateTlsClientCredentials() (credentials.TransportCredentials, error) {
	clientCert, caCertPool, err := manager.CertLoader.GetCertificateAndCaPool()
	if err != nil {
		return nil, err
	}
	// Create tls client credentials
	config := &tls.Config{
		Certificates: []tls.Certificate{*clientCert},
		RootCAs:      caCertPool,
	}

	return credentials.NewTLS(config), nil
}

func (manager *TlsCredentialManager) CreateTlsServerCredentials() (credentials.TransportCredentials, error) {
	serverCert, caCertPool, err := manager.CertLoader.GetCertificateAndCaPool()
	if err != nil {
		return nil, err
	}
	// Create tls server credentials
	config := &tls.Config{
		Certificates: []tls.Certificate{*serverCert},
		ClientCAs:    caCertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}

	return credentials.NewTLS(config), nil
}

func GetX509KeyPairFromCertBytes(certBytes *CertBytes) (*tls.Certificate, error) {
	cert, err := tls.X509KeyPair(certBytes.Crt, certBytes.Key)
	if err != nil {
		return nil, err
	}
	return &cert, nil
}
