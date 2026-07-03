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
