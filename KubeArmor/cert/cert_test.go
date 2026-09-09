package cert

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// Helper fixtures

// generateTestCA produces a fully signed CA certificate/key pair by going
// through GenerateCA → GetCertKeyPairFromCertBytes. The returned CertKeyPair
// contains a *x509.Certificate whose Raw field is populated (i.e. real DER
// bytes), so leaf certs signed with it will genuinely chain to this CA.
func generateTestCA(t *testing.T) *CertKeyPair {
	t.Helper()
	cfg := DefaultKubeArmorCAConfig
	cfg.NotAfter = time.Now().Add(1 * time.Hour)
	caBytes, err := GenerateCA(&cfg)
	if err != nil {
		t.Fatalf("Failed to generate CA bytes: %v", err)
	}
	keyPair, err := GetCertKeyPairFromCertBytes(caBytes)
	if err != nil {
		t.Fatalf("Failed to parse CA key pair: %v", err)
	}
	return keyPair
}

func generateTestCertBytes(t *testing.T) *CertBytes {
	t.Helper()
	ca := generateTestCA(t)
	cfg := DefaultKubeArmorServerConfig
	cfg.NotAfter = time.Now().Add(1 * time.Hour)
	certBytes, err := GenerateSelfSignedCert(ca, &cfg)
	if err != nil {
		t.Fatalf("Failed to generate test self-signed cert: %v", err)
	}
	return certBytes
}

func writeCertFiles(t *testing.T, dir string, certBytes *CertBytes) (string, string) {
	t.Helper()
	certFile := filepath.Join(dir, "tls.crt")
	keyFile := filepath.Join(dir, "tls.key")
	if err := os.WriteFile(certFile, certBytes.Crt, 0644); err != nil {
		t.Fatalf("Failed to write cert file: %v", err)
	}
	if err := os.WriteFile(keyFile, certBytes.Key, 0600); err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}
	return certFile, keyFile
}

// Tests
func TestGetPemCertFromx509Cert(t *testing.T) {
	ca := generateTestCA(t)
	pemBytes := GetPemCertFromx509Cert(*ca.Crt)
	if len(pemBytes) == 0 {
		t.Fatal("Expected non-empty PEM bytes")
	}
	if !bytes.HasPrefix(pemBytes, []byte("-----BEGIN CERTIFICATE-----")) {
		t.Errorf("Expected PEM prefix, got: %s", string(pemBytes[:30]))
	}
}

func TestCertPaths(t *testing.T) {
	base := "/tmp/base"

	caPath := GetCACertPath(base)
	if caPath.Base != base || caPath.CertFile != "ca.crt" || caPath.KeyFile != "ca.key" {
		t.Errorf("Unexpected CA path: %+v", caPath)
	}

	clientPath := GetClientCertPath(base)
	if clientPath.Base != base || clientPath.CertFile != "client.crt" || clientPath.KeyFile != "client.key" {
		t.Errorf("Unexpected Client path: %+v", clientPath)
	}

	serverPath := GetServerCertPath(base)
	if serverPath.Base != base || serverPath.CertFile != "server.crt" || serverPath.KeyFile != "server.key" {
		t.Errorf("Unexpected Server path: %+v", serverPath)
	}
}

func TestGenerateCert(t *testing.T) {
	t.Run("ValidConfig", func(t *testing.T) {
		cfg := DefaultKubeArmorServerConfig
		cfg.NotAfter = time.Now().Add(1 * time.Hour)
		cfg.DNS = []string{"localhost"}
		cfg.IPs = []string{"127.0.0.1"}

		keyPair, err := GenerateCert(&cfg)
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
		if keyPair == nil || keyPair.Crt == nil || keyPair.Key == nil {
			t.Fatal("Expected non-nil keyPair with crt and key")
		}
		if keyPair.Crt.Subject.CommonName != cfg.CN {
			t.Errorf("Expected CN %s, got %s", cfg.CN, keyPair.Crt.Subject.CommonName)
		}
		if len(keyPair.Crt.DNSNames) != 1 || keyPair.Crt.DNSNames[0] != "localhost" {
			t.Errorf("Expected DNS localhost, got %v", keyPair.Crt.DNSNames)
		}
		if len(keyPair.Crt.IPAddresses) != 1 || keyPair.Crt.IPAddresses[0].String() != "127.0.0.1" {
			t.Errorf("Expected IP 127.0.0.1, got %v", keyPair.Crt.IPAddresses)
		}
		if keyPair.Crt.IsCA {
			t.Error("Expected IsCA to be false")
		}
	})

	t.Run("CAConfig", func(t *testing.T) {
		cfg := DefaultKubeArmorCAConfig
		cfg.NotAfter = time.Now().Add(1 * time.Hour)
		keyPair, err := GenerateCert(&cfg)
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
		if !keyPair.Crt.IsCA {
			t.Error("Expected IsCA to be true")
		}
		if !keyPair.Crt.BasicConstraintsValid {
			t.Error("Expected BasicConstraintsValid to be true")
		}
	})
}

func TestGenerateCA(t *testing.T) {
	cfg := DefaultKubeArmorCAConfig
	cfg.NotAfter = time.Now().Add(1 * time.Hour)
	certBytes, err := GenerateCA(&cfg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if len(certBytes.Crt) == 0 || len(certBytes.Key) == 0 {
		t.Fatal("Expected non-empty cert and key bytes")
	}

	block, _ := pem.Decode(certBytes.Crt)
	if block == nil {
		t.Fatal("Failed to decode cert PEM")
	}
	crt, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse cert: %v", err)
	}
	if !crt.IsCA {
		t.Error("Expected generated CA cert to have IsCA=true")
	}
}

func TestGenerateSelfSignedCert(t *testing.T) {
	ca := generateTestCA(t)

	t.Run("ValidCA", func(t *testing.T) {
		cfg := DefaultKubeArmorServerConfig
		cfg.NotAfter = time.Now().Add(1 * time.Hour)
		certBytes, err := GenerateSelfSignedCert(ca, &cfg)
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
		if len(certBytes.Crt) == 0 || len(certBytes.Key) == 0 {
			t.Fatal("Expected non-empty cert and key bytes")
		}
	})

}

func TestGetCertKeyPairFromCertBytes(t *testing.T) {
	t.Run("ValidBytes", func(t *testing.T) {
		certBytes := generateTestCertBytes(t)
		keyPair, err := GetCertKeyPairFromCertBytes(certBytes)
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
		if keyPair.Crt == nil || keyPair.Key == nil {
			t.Fatal("Expected parsed key pair to have non-nil crt and key")
		}
	})

}

func TestReadCertFromFile(t *testing.T) {
	certBytes := generateTestCertBytes(t)

	t.Run("HappyPath", func(t *testing.T) {
		dir := t.TempDir()
		writeCertFiles(t, dir, certBytes)

		path := &CertPath{
			Base:     dir,
			CertFile: "tls.crt",
			KeyFile:  "tls.key",
		}
		loaded, err := ReadCertFromFile(path)
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
		if !bytes.Equal(loaded.Crt, certBytes.Crt) || !bytes.Equal(loaded.Key, certBytes.Key) {
			t.Error("Loaded bytes do not match written bytes")
		}
	})

	t.Run("MissingCertFile", func(t *testing.T) {
		dir := t.TempDir()
		path := &CertPath{
			Base:     dir,
			CertFile: "tls.crt",
			KeyFile:  "tls.key",
		}
		_, err := ReadCertFromFile(path)
		if err == nil {
			t.Fatal("Expected error for missing cert file")
		}
	})

	t.Run("MissingKeyFile", func(t *testing.T) {
		dir := t.TempDir()
		certFile := filepath.Join(dir, "tls.crt")
		if err := os.WriteFile(certFile, certBytes.Crt, 0644); err != nil {
			t.Fatalf("Failed to write cert file: %v", err)
		}

		path := &CertPath{
			Base:     dir,
			CertFile: "tls.crt",
			KeyFile:  "tls.key",
		}
		_, err := ReadCertFromFile(path)
		if err == nil {
			t.Fatal("Expected error for missing key file")
		}
	})

	t.Run("CertOnly", func(t *testing.T) {
		dir := t.TempDir()
		certFile := filepath.Join(dir, "tls.crt")
		if err := os.WriteFile(certFile, certBytes.Crt, 0644); err != nil {
			t.Fatalf("Failed to write cert file: %v", err)
		}

		path := &CertPath{
			Base:     dir,
			CertFile: "tls.crt",
			KeyFile:  "tls.key",
			CertOnly: true,
		}
		loaded, err := ReadCertFromFile(path)
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
		if !bytes.Equal(loaded.Crt, certBytes.Crt) {
			t.Error("Loaded cert bytes do not match")
		}
		if len(loaded.Key) != 0 {
			t.Errorf("Expected empty key bytes for CertOnly=true, got %d bytes", len(loaded.Key))
		}
	})
}

func TestReadCertFromK8sSecret(t *testing.T) {
	certBytes := generateTestCertBytes(t)

	t.Run("HappyPath", func(t *testing.T) {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-secret",
				Namespace: "default",
			},
			Data: map[string][]byte{
				"tls.crt": certBytes.Crt,
				"tls.key": certBytes.Key,
			},
		}
		client := fake.NewSimpleClientset(secret)

		loaded, err := ReadCertFromK8sSecret(client, "default", "test-secret")
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
		if !bytes.Equal(loaded.Crt, certBytes.Crt) || !bytes.Equal(loaded.Key, certBytes.Key) {
			t.Error("Loaded bytes from secret do not match")
		}
	})

	t.Run("SecretNotFound", func(t *testing.T) {
		client := fake.NewSimpleClientset()
		_, err := ReadCertFromK8sSecret(client, "default", "missing-secret")
		if err == nil {
			t.Fatal("Expected error for missing secret")
		}
	})
}
