// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

// Package cert is responsible for generating certs dynamically and loading the certs from external sources.
package cert

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
)

const (
	// ORG kubearmor
	KubeArmor_ORG string = "kubearmor"
	KubeArmor_CN  string = "kubearmor"
)

var DefaultKubeArmorServerConfig = CertConfig{
	CN:           KubeArmor_CN,
	Organization: KubeArmor_ORG,
	KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
}

var DefaultKubeArmorClientConfig = CertConfig{
	CN:           KubeArmor_CN,
	Organization: KubeArmor_ORG,
	KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
}

var DefaultKubeArmorCAConfig = CertConfig{
	CN:           KubeArmor_CN,
	Organization: KubeArmor_ORG,
	IsCa:         true,
	KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
}

type CertConfig struct {
	CN           string // Common Name
	Organization string
	DNS          []string
	IPs          []string
	IsCa         bool
	KeyUsage     x509.KeyUsage
	ExtKeyUsage  []x509.ExtKeyUsage
	NotAfter     time.Time
}

// CertKeyPair type
type CertKeyPair struct {
	Crt *x509.Certificate
	Key *rsa.PrivateKey
}

// CertBytes type
type CertBytes struct {
	Crt []byte
	Key []byte
}

type CertPath struct {
	Base     string
	CertFile string
	KeyFile  string // Not Required if CertOnly:true
	CertOnly bool   // if true read certificate only
}

func GetPemCertFromx509Cert(cert x509.Certificate) []byte {
	certPem := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}
	var pemBuffer bytes.Buffer
	err := pem.Encode(&pemBuffer, certPem)
	if err != nil {
		klog.Error("error while encoding certificate to pem format", err)
	}
	return pemBuffer.Bytes()
}

// GetCACertPath func returns CA certificate (full) path
func GetCACertPath(base string) CertPath {
	return CertPath{
		Base:     base,
		CertFile: "ca.crt",
		KeyFile:  "ca.key",
	}
}

// GetClientCertPath func returns client certificate (full) path
func GetClientCertPath(base string) CertPath {
	return CertPath{
		Base:     base,
		CertFile: "client.crt",
		KeyFile:  "client.key",
	}
}

// GetServerCertPath func returns server certificate (full) path
func GetServerCertPath(base string) CertPath {
	return CertPath{
		Base:     base,
		CertFile: "server.crt",
		KeyFile:  "server.key",
	}
}

// certPairExists checks if the certificate pair (certificate and key) exists at the given path
func certPairExists(path *CertPath) bool {
	if _, err := os.Stat(filepath.Join(path.Base, path.CertFile)); err != nil {
		return false
	}

	if !path.CertOnly {
		if _, err := os.Stat(filepath.Join(path.Base, path.KeyFile)); err != nil {
			return false
		}
	}

	return true
}

// EnsureDevelopmentPKI ensures the complete development PKI exists.
// It bootstraps the CA, server certificate and client certificate
// on first startup. Subsequent startups simply reuse the existing
// certificates.
func EnsureDevelopmentPKI(base string, nodeIP string) error {
	if err := os.MkdirAll(base, 0750); err != nil {
		return err
	}

	caPath := GetCACertPath(base)
	serverPath := GetServerCertPath(base)
	clientPath := GetClientCertPath(base)

	// ------------------------------------------------------------------
	// Ensure CA
	// ------------------------------------------------------------------

	var ca *CertKeyPair

	if !certPairExists(&caPath) {
		klog.Infof("Generating development CA")

		DefaultKubeArmorCAConfig.NotAfter = time.Now().AddDate(10, 0, 0)

		caBytes, err := GenerateCA(&DefaultKubeArmorCAConfig)
		if err != nil {
			return err
		}

		if err := os.WriteFile(
			filepath.Join(caPath.Base, caPath.CertFile),
			caBytes.Crt,
			0600,
		); err != nil {
			return err
		}

		if err := os.WriteFile(
			filepath.Join(caPath.Base, caPath.KeyFile),
			caBytes.Key,
			0600,
		); err != nil {
			return err
		}

		ca, err = GetCertKeyPairFromCertBytes(caBytes)
		if err != nil {
			return err
		}
	} else {
		caBytes, err := ReadCertFromFile(&caPath)
		if err != nil {
			return err
		}

		ca, err = GetCertKeyPairFromCertBytes(caBytes)
		if err != nil {
			return err
		}
	}

	// ------------------------------------------------------------------
	// Ensure Server Certificate
	// ------------------------------------------------------------------

	if !certPairExists(&serverPath) {
		klog.Infof("Generating development server certificate")

		cfg := DefaultKubeArmorServerConfig
		cfg.DNS = []string{"localhost", "kubearmor"}
		cfg.IPs = []string{"127.0.0.1", "::1"}
		if nodeIP != "" {
			cfg.IPs = append(cfg.IPs, nodeIP)
		}
		cfg.NotAfter = time.Now().AddDate(1, 0, 0)

		serverBytes, err := GenerateSelfSignedCert(ca, &cfg)
		if err != nil {
			return err
		}

		if err := os.WriteFile(
			filepath.Join(serverPath.Base, serverPath.CertFile),
			serverBytes.Crt,
			0600,
		); err != nil {
			return err
		}

		if err := os.WriteFile(
			filepath.Join(serverPath.Base, serverPath.KeyFile),
			serverBytes.Key,
			0600,
		); err != nil {
			return err
		}
	}

	// ------------------------------------------------------------------
	// Ensure Client Certificate
	// ------------------------------------------------------------------

	if !certPairExists(&clientPath) {
		klog.Infof("Generating development client certificate")

		cfg := DefaultKubeArmorClientConfig
		cfg.NotAfter = time.Now().AddDate(1, 0, 0)

		clientBytes, err := GenerateSelfSignedCert(ca, &cfg)
		if err != nil {
			return err
		}

		if err := os.WriteFile(
			filepath.Join(clientPath.Base, clientPath.CertFile),
			clientBytes.Crt,
			0600,
		); err != nil {
			return err
		}

		if err := os.WriteFile(
			filepath.Join(clientPath.Base, clientPath.KeyFile),
			clientBytes.Key,
			0600,
		); err != nil {
			return err
		}
	}

	return nil
}

func GetCertKeyPairFromCertBytes(certBytes *CertBytes) (*CertKeyPair, error) {
	// Parse CA certificate and key
	certPem, _ := pem.Decode(certBytes.Crt)
	if certPem == nil {
		return nil, fmt.Errorf("failed to decode CA certificate")
	}
	keyPem, _ := pem.Decode(certBytes.Key)
	if keyPem == nil {
		return nil, fmt.Errorf("failed to decode CA private key")
	}

	crt, err := x509.ParseCertificate(certPem.Bytes)
	if err != nil {
		klog.Error("Error parsing CA certificate:", err)
		return nil, err
	}

	key, err := x509.ParsePKCS1PrivateKey(keyPem.Bytes)
	if err != nil {
		klog.Error("Error parsing CA private key:", err)
		return nil, err
	}

	return &CertKeyPair{
		Crt: crt,
		Key: key,
	}, nil
}

// ReadCertFromFile func reads certificate key pair from the given path
func ReadCertFromFile(certPath *CertPath) (*CertBytes, error) {
	var certBytes, keyBytes []byte
	certFile := filepath.Clean(filepath.Join(certPath.Base, certPath.CertFile))
	keyFile := filepath.Clean(filepath.Join(certPath.Base, certPath.KeyFile))

	// Check if certificate file exists
	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		klog.Error("certificate file does not exist:", err)
		return nil, err
	}

	certBytes, err := os.ReadFile(certFile)
	if err != nil {
		klog.Error("Error reading CA certificate file:", err)
		return nil, err
	}

	if !certPath.CertOnly {
		// Check if key file exists
		if _, err := os.Stat(keyFile); os.IsNotExist(err) {
			klog.Error("CA key file does not exist:", err)
			return nil, err
		}

		keyBytes, err = os.ReadFile(keyFile)
		if err != nil {
			klog.Error("Error reading CA key file:", err)
			return nil, err
		}
	}

	return &CertBytes{
		Crt: certBytes,
		Key: keyBytes,
	}, nil
}

// ReadCertFromK8sSecret func reads cert from the k8s tls secret
// it assumes the cert and key file exists with tls.crt and tls.key names respectively
// that is true in case of kubernetes.io/tls secret type,
// https://kubernetes.io/docs/concepts/configuration/secret/#tls-secrets
func ReadCertFromK8sSecret(client *kubernetes.Clientset, namespace, secret string) (*CertBytes, error) {

	// get secret
	cert, err := client.CoreV1().Secrets(namespace).Get(context.Background(), secret, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	return &CertBytes{
		Crt: cert.Data["tls.crt"],
		Key: cert.Data["tls.key"],
	}, nil
}

func GenerateCA(cfg *CertConfig) (*CertBytes, error) {
	crtTemp, err := GenerateCert(cfg)
	if err != nil {
		klog.Errorf("error generating ca cert: %s\n", err)
		return &CertBytes{}, err
	}
	crtBytes, err := GenerateSelfSignedCert(crtTemp, cfg)
	if err != nil {
		return &CertBytes{}, nil
	}
	return &CertBytes{
		Crt: crtBytes.Crt,
		Key: crtBytes.Key,
	}, nil
}

func GenerateCert(cfg *CertConfig) (*CertKeyPair, error) {
	// Generate a new RSA private key for the server
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		klog.Error("error generating cert private key:", err)
		return nil, err
	}

	// Create a template for the certificate
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cfg.CN, Organization: []string{cfg.Organization}},
		NotBefore:             time.Now(),
		NotAfter:              cfg.NotAfter,
		KeyUsage:              cfg.KeyUsage,
		ExtKeyUsage:           cfg.ExtKeyUsage,
		IsCA:                  cfg.IsCa,
		BasicConstraintsValid: true,
	}
	template.DNSNames = append(template.DNSNames, cfg.DNS...)

	for _, ip := range cfg.IPs {
		template.IPAddresses = append(template.IPAddresses, net.ParseIP(ip))
	}

	return &CertKeyPair{Crt: &template, Key: key}, nil
}

// GenerateSelfSignedCert func generates cert and key signed by provided CA
func GenerateSelfSignedCert(ca *CertKeyPair, cfg *CertConfig) (*CertBytes, error) {
	certKeyPair, err := GenerateCert(cfg)
	if err != nil {
		return nil, err
	}

	// Create the certificate signed by the CA
	certBytes, err := x509.CreateCertificate(rand.Reader, certKeyPair.Crt, ca.Crt, &certKeyPair.Key.PublicKey, ca.Key)
	if err != nil {
		klog.Error("Error creating certificate:", err)
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(certKeyPair.Key)})

	if certPEM == nil || keyPEM == nil {
		return nil, fmt.Errorf("error encoding certificate")
	}

	return &CertBytes{
		Crt: certPEM,
		Key: keyPEM,
	}, nil
}
