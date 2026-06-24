package cert

import (
	"crypto/x509"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestSelfSignedCertLoader(t *testing.T) {
	t.Run("HappyPath", func(t *testing.T) {
		cfg := DefaultKubeArmorCAConfig
		cfg.NotAfter = time.Now().Add(1 * time.Hour)
		caBytes, _ := GenerateCA(&cfg)
		dir := t.TempDir()
		writeCertFiles(t, dir, caBytes)

		loader := &SelfSignedCertLoader{
			CaCertPath: CertPath{
				Base:     dir,
				CertFile: "tls.crt",
				KeyFile:  "tls.key",
			},
			CertConfig: DefaultKubeArmorServerConfig,
		}
		loader.CertConfig.NotAfter = time.Now().Add(1 * time.Hour)

		cert, pool, err := loader.GetCertificateAndCaPool()
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
		if cert == nil || pool == nil {
			t.Fatal("Expected non-nil cert and pool")
		}
	})

	t.Run("MissingFile", func(t *testing.T) {
		dir := t.TempDir()
		loader := &SelfSignedCertLoader{
			CaCertPath: CertPath{Base: dir, CertFile: "missing.crt", KeyFile: "missing.key"},
			CertConfig: DefaultKubeArmorServerConfig,
		}
		_, _, err := loader.GetCertificateAndCaPool()
		if err == nil {
			t.Fatal("Expected error for missing file")
		}
	})
}

func TestExternalCertLoader(t *testing.T) {
	t.Run("HappyPath", func(t *testing.T) {
		// Generate a real CA via GenerateCA so the PEM bytes are fully signed.
		caCfg := DefaultKubeArmorCAConfig
		caCfg.NotAfter = time.Now().Add(1 * time.Hour)
		caBytes, err := GenerateCA(&caCfg)
		if err != nil {
			t.Fatalf("Failed to generate CA: %v", err)
		}
		caDir := t.TempDir()
		writeCertFiles(t, caDir, caBytes)

		// Generate a leaf cert signed by that SAME CA.
		caKeyPair, err := GetCertKeyPairFromCertBytes(caBytes)
		if err != nil {
			t.Fatalf("Failed to parse CA key pair: %v", err)
		}
		leafCfg := DefaultKubeArmorServerConfig
		leafCfg.NotAfter = time.Now().Add(1 * time.Hour)
		certBytes, err := GenerateSelfSignedCert(caKeyPair, &leafCfg)
		if err != nil {
			t.Fatalf("Failed to generate leaf cert: %v", err)
		}
		certDir := t.TempDir()
		writeCertFiles(t, certDir, certBytes)

		loader := &ExternalCertLoader{
			CaCertPath: CertPath{Base: caDir, CertFile: "tls.crt"},
			CertPath:   CertPath{Base: certDir, CertFile: "tls.crt", KeyFile: "tls.key"},
		}

		cred, pool, err := loader.GetCertificateAndCaPool()
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
		if cred == nil || pool == nil {
			t.Fatal("Expected non-nil cert and pool")
		}

		// Verify the leaf cert actually chains to the CA pool that was loaded.
		leafX509, err := x509.ParseCertificate(cred.Certificate[0])
		if err != nil {
			t.Fatalf("Failed to parse leaf cert from credentials: %v", err)
		}
		_, err = leafX509.Verify(x509.VerifyOptions{Roots: pool})
		if err != nil {
			t.Errorf("Leaf cert does not chain to loaded CA pool: %v", err)
		}
	})

	t.Run("MissingCA", func(t *testing.T) {
		certBytes := generateTestCertBytes(t)
		certDir := t.TempDir()
		writeCertFiles(t, certDir, certBytes)

		loader := &ExternalCertLoader{
			CaCertPath: CertPath{Base: "/nonexistent", CertFile: "tls.crt"},
			CertPath:   CertPath{Base: certDir, CertFile: "tls.crt", KeyFile: "tls.key"},
		}
		_, _, err := loader.GetCertificateAndCaPool()
		if err == nil {
			t.Fatal("Expected error")
		}
	})

	t.Run("MissingLeaf", func(t *testing.T) {
		cfg := DefaultKubeArmorCAConfig
		cfg.NotAfter = time.Now().Add(1 * time.Hour)
		caBytes, _ := GenerateCA(&cfg)
		caDir := t.TempDir()
		writeCertFiles(t, caDir, caBytes)

		loader := &ExternalCertLoader{
			CaCertPath: CertPath{Base: caDir, CertFile: "tls.crt"},
			CertPath:   CertPath{Base: "/nonexistent", CertFile: "tls.crt", KeyFile: "tls.key"},
		}
		_, _, err := loader.GetCertificateAndCaPool()
		if err == nil {
			t.Fatal("Expected error")
		}
	})
}

func TestK8sCertLoader(t *testing.T) {
	t.Run("HappyPath", func(t *testing.T) {
		cfg := DefaultKubeArmorCAConfig
		cfg.NotAfter = time.Now().Add(1 * time.Hour)
		caBytes, _ := GenerateCA(&cfg)

		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-secret",
				Namespace: "default",
			},
			Data: map[string][]byte{
				"tls.crt": caBytes.Crt,
				"tls.key": caBytes.Key,
			},
		}
		client := fake.NewSimpleClientset(secret)

		loader := &K8sCertLoader{
			Namespace:  "default",
			SecretName: "test-secret",
			K8sClient:  client,
			CertConfig: DefaultKubeArmorServerConfig,
		}

		cert, pool, err := loader.GetCertificateAndCaPool()
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
		if cert == nil || pool == nil {
			t.Fatal("Expected non-nil cert and pool")
		}
	})

	t.Run("MissingCA", func(t *testing.T) {
		client := fake.NewSimpleClientset()

		loader := &K8sCertLoader{
			Namespace:  "default",
			SecretName: "missing-secret",
			K8sClient:  client,
			CertConfig: DefaultKubeArmorServerConfig,
		}

		_, _, err := loader.GetCertificateAndCaPool()
		if err == nil {
			t.Fatal("Expected error")
		}
	})
}
