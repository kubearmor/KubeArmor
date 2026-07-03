// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package cert

import (
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
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

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func containsIP(values []net.IP, want string) bool {
	wantIP := net.ParseIP(want)
	for _, value := range values {
		if value.Equal(wantIP) {
			return true
		}
	}
	return false
}

func parseCertificate(t *testing.T, certBytes []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(certBytes)
	if block == nil {
		t.Fatalf("expected certificate PEM")
	}
	crt, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}
	return crt
}

func TestKubeArmorServerSANs(t *testing.T) {
	t.Setenv("KUBEARMOR_NAMESPACE", "kubearmor")

	dnsNames, ipNames := KubeArmorServerSANs("10.0.0.5", "node-a", "kubearmor", "10.0.0.5")

	for _, want := range []string{
		"localhost",
		"kubearmor",
		"node-a",
		"kubearmor.kubearmor",
		"kubearmor.kubearmor.svc",
		"kubearmor.kubearmor.svc.cluster.local",
	} {
		if !containsString(dnsNames, want) {
			t.Fatalf("expected DNS SAN %q in %v", want, dnsNames)
		}
	}

	for _, want := range []string{"127.0.0.1", "::1", "10.0.0.5"} {
		if !containsString(ipNames, want) {
			t.Fatalf("expected IP SAN %q in %v", want, ipNames)
		}
	}
}

func TestGenerateCertSkipsInvalidIPSANs(t *testing.T) {
	cfg := DefaultKubeArmorServerConfig
	cfg.IPs = []string{"10.0.0.5", "not-an-ip"}
	cfg.NotAfter = time.Now().Add(time.Hour)

	certKeyPair, err := GenerateCert(&cfg)
	if err != nil {
		t.Fatalf("GenerateCert failed: %v", err)
	}
	if !containsIP(certKeyPair.Crt.IPAddresses, "10.0.0.5") {
		t.Fatalf("expected valid IP SAN in %v", certKeyPair.Crt.IPAddresses)
	}
	if len(certKeyPair.Crt.IPAddresses) != 1 {
		t.Fatalf("expected invalid IP SAN to be skipped, got %v", certKeyPair.Crt.IPAddresses)
	}
}

func TestEnsureDevelopmentPKIIncludesNodeAndServiceSANs(t *testing.T) {
	t.Setenv("KUBEARMOR_NAMESPACE", "kubearmor")

	base := t.TempDir()
	if err := EnsureDevelopmentPKI(base, "10.0.0.5", "node-a"); err != nil {
		t.Fatalf("EnsureDevelopmentPKI failed: %v", err)
	}

	crt := parseCertificate(t, mustReadFile(t, filepath.Join(base, "server.crt")))
	for _, want := range []string{"localhost", "kubearmor", "node-a", "kubearmor.kubearmor.svc"} {
		if !containsString(crt.DNSNames, want) {
			t.Fatalf("expected DNS SAN %q in %v", want, crt.DNSNames)
		}
	}
	if !containsIP(crt.IPAddresses, "10.0.0.5") {
		t.Fatalf("expected node IP SAN in %v", crt.IPAddresses)
	}
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read %s: %v", path, err)
	}
	return data
}
