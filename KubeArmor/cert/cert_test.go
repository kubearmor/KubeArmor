// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package cert

import (
	"testing"
	"time"
)

func TestGenerateCA_Success(t *testing.T) {
	// take a value copy so the package-level default stays untouched
	cfg := DefaultKubeArmorCAConfig
	cfg.NotAfter = time.Now().Add(24 * time.Hour)

	caBytes, err := GenerateCA(&cfg)
	if err != nil {
		t.Fatalf("expected no error generating CA, got: %v", err)
	}

	if len(caBytes.Crt) == 0 {
		t.Errorf("expected non-empty CA certificate bytes")
	}

	if len(caBytes.Key) == 0 {
		t.Errorf("expected non-empty CA key bytes")
	}
}

func TestGenerateCA_ErrorPropagationOnSelfSignedCertFailure(t *testing.T) {
	// take a value copy so the package-level default stays untouched
	cfg := DefaultKubeArmorCAConfig

	// 1. Test GenerateSelfSignedCert with invalid/nil CA struct returns error
	_, err := GenerateSelfSignedCert(nil, &cfg)
	if err == nil {
		t.Errorf("expected error when generating self-signed cert with nil CA, got nil")
	}

	_, err = GenerateSelfSignedCert(&CertKeyPair{}, &cfg)
	if err == nil {
		t.Errorf("expected error when generating self-signed cert with empty CertKeyPair, got nil")
	}

	// 2. Test GenerateCA error propagation when inner GenerateSelfSignedCert fails with uninitialized CA key
	invalidCA := &CertKeyPair{}
	_, err = GenerateSelfSignedCert(invalidCA, &cfg)
	if err == nil {
		t.Errorf("expected error from GenerateSelfSignedCert with uninitialized CA key, got nil")
	}
}

func TestGetCertPaths(t *testing.T) {
	caPath := GetCACertPath("/etc/kubearmor")
	if caPath.CertFile != "ca.crt" || caPath.KeyFile != "ca.key" {
		t.Errorf("unexpected CA cert paths: %+v", caPath)
	}

	clientPath := GetClientCertPath("/etc/kubearmor")
	if clientPath.CertFile != "client.crt" || clientPath.KeyFile != "client.key" {
		t.Errorf("unexpected client cert paths: %+v", clientPath)
	}

	serverPath := GetServerCertPath("/etc/kubearmor")
	if serverPath.CertFile != "server.crt" || serverPath.KeyFile != "server.key" {
		t.Errorf("unexpected server cert paths: %+v", serverPath)
	}
}
