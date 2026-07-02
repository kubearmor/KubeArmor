package cert

import (
	"crypto/x509"
	"testing"
)

func TestGenerateCA_Success(t *testing.T) {
	cfg := &CertConfig{
		CN:           "test-ca",
		Organization: "test-org",
		IsCa:         true,
		KeyUsage:     x509.KeyUsageCertSign,
	}

	certBytes, err := GenerateCA(cfg)
	if err != nil {
		t.Fatalf("GenerateCA() expected no error, got: %v", err)
	}
	if len(certBytes.Crt) == 0 {
		t.Error("GenerateCA() returned empty certificate")
	}
	if len(certBytes.Key) == 0 {
		t.Error("GenerateCA() returned empty key")
	}
}

func TestGenerateSelfSignedCert_Success(t *testing.T) {
	ca, err := GenerateCA(&CertConfig{
		CN:           "test-root",
		Organization: "test",
		IsCa:         true,
		KeyUsage:     x509.KeyUsageCertSign,
	})
	if err != nil {
		t.Fatalf("failed to generate CA: %v", err)
	}

	caPair, err := GetCertKeyPairFromCertBytes(ca)
	if err != nil {
		t.Fatalf("failed to parse CA cert bytes: %v", err)
	}

	cfg := &CertConfig{
		CN:           "test-leaf",
		Organization: "test",
	}

	cert, err := GenerateSelfSignedCert(caPair, cfg)
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert() expected no error, got: %v", err)
	}
	if len(cert.Crt) == 0 {
		t.Error("GenerateSelfSignedCert() returned empty certificate")
	}
	if len(cert.Key) == 0 {
		t.Error("GenerateSelfSignedCert() returned empty key")
	}
}

func TestGetPemCertFromx509Cert(t *testing.T) {
	ca, err := GenerateCA(&CertConfig{
		CN:           "test",
		Organization: "test",
		IsCa:         true,
		KeyUsage:     x509.KeyUsageCertSign,
	})
	if err != nil {
		t.Fatalf("GenerateCA() failed: %v", err)
	}

	caPair, err := GetCertKeyPairFromCertBytes(ca)
	if err != nil {
		t.Fatalf("GetCertKeyPairFromCertBytes() failed: %v", err)
	}

	pemBytes := GetPemCertFromx509Cert(*caPair.Crt)
	if len(pemBytes) == 0 {
		t.Error("GetPemCertFromx509Cert() returned empty bytes")
	}
}
