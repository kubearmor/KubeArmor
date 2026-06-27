package cert

import (
	"crypto/tls"
	"crypto/x509"
	"testing"
)

type mockCertLoader struct {
	cert *tls.Certificate
	pool *x509.CertPool
	err  error
}

func (m *mockCertLoader) GetCertificateAndCaPool() (*tls.Certificate, *x509.CertPool, error) {
	return m.cert, m.pool, m.err
}

func TestNewTlsCredentialManager(t *testing.T) {
	t.Run("SelfCertProvider_NoSecret", func(t *testing.T) {
		cfg := &TlsConfig{
			CertProvider:         SelfCertProvider,
			ReadCACertFromSecret: false,
		}
		mgr := NewTlsCredentialManager(cfg)
		if mgr == nil {
			t.Fatal("Expected non-nil manager")
		}
		if _, ok := mgr.CertLoader.(*SelfSignedCertLoader); !ok {
			t.Error("Expected CertLoader to be SelfSignedCertLoader")
		}
	})

	t.Run("SelfCertProvider_WithSecret", func(t *testing.T) {
		cfg := &TlsConfig{
			CertProvider:         SelfCertProvider,
			ReadCACertFromSecret: true,
		}
		mgr := NewTlsCredentialManager(cfg)
		if mgr == nil {
			t.Fatal("Expected non-nil manager")
		}
		if _, ok := mgr.CertLoader.(*K8sCertLoader); !ok {
			t.Error("Expected CertLoader to be K8sCertLoader")
		}
	})

	t.Run("ExternalCertProvider", func(t *testing.T) {
		cfg := &TlsConfig{
			CertProvider: ExternalCertProvider,
		}
		mgr := NewTlsCredentialManager(cfg)
		if mgr == nil {
			t.Fatal("Expected non-nil manager")
		}
		if _, ok := mgr.CertLoader.(*ExternalCertLoader); !ok {
			t.Error("Expected CertLoader to be ExternalCertLoader")
		}
	})

	t.Run("UnknownProvider", func(t *testing.T) {
		cfg := &TlsConfig{
			CertProvider: "unknown",
		}
		mgr := NewTlsCredentialManager(cfg)
		if mgr != nil {
			t.Fatal("Expected nil manager for unknown provider")
		}
	})
}

func TestCreateTlsCredentials(t *testing.T) {
	t.Run("ClientCredentials", func(t *testing.T) {
		certBytes := generateTestCertBytes(t)
		tlsCert, _ := GetX509KeyPairFromCertBytes(certBytes)
		pool := x509.NewCertPool()

		loader := &mockCertLoader{cert: tlsCert, pool: pool}
		mgr := &TlsCredentialManager{CertLoader: loader}

		creds, err := mgr.CreateTlsClientCredentials()
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
		if creds == nil {
			t.Fatal("Expected non-nil credentials")
		}
	})

	t.Run("ServerCredentials", func(t *testing.T) {
		certBytes := generateTestCertBytes(t)
		tlsCert, _ := GetX509KeyPairFromCertBytes(certBytes)
		pool := x509.NewCertPool()

		loader := &mockCertLoader{cert: tlsCert, pool: pool}
		mgr := &TlsCredentialManager{CertLoader: loader}

		creds, err := mgr.CreateTlsServerCredentials()
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
		if creds == nil {
			t.Fatal("Expected non-nil credentials")
		}
	})
}

func TestGetX509KeyPairFromCertBytes(t *testing.T) {
	t.Run("HappyPath", func(t *testing.T) {
		certBytes := generateTestCertBytes(t)
		tlsCert, err := GetX509KeyPairFromCertBytes(certBytes)
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
		if tlsCert == nil {
			t.Fatal("Expected non-nil tls.Certificate")
		}
	})

	t.Run("MalformedPEM", func(t *testing.T) {
		certBytes := &CertBytes{Crt: []byte("bad"), Key: []byte("bad")}
		_, err := GetX509KeyPairFromCertBytes(certBytes)
		if err == nil {
			t.Fatal("Expected error for malformed PEM")
		}
	})
}
