// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package common

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"time"
)

// GeneratePki - generate pub/priv keypair
func GeneratePki(namespace string, serviceName string) (*bytes.Buffer, *bytes.Buffer, *bytes.Buffer, *bytes.Buffer, error) {
	ca, cakey, err := GenerateCA()
	if err != nil {
		empty := bytes.NewBuffer([]byte{})
		return empty, empty, empty, empty, err
	}
	csr, csrkey, err := GenerateCSR(namespace, serviceName)
	if err != nil {
		empty := bytes.NewBuffer([]byte{})
		return empty, empty, empty, empty, err
	}
	crt, err := SignCSR(ca, cakey, csr, csrkey)
	if err != nil {
		empty := bytes.NewBuffer([]byte{})
		return empty, empty, empty, empty, err
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &cakey.PublicKey, cakey)
	if err != nil {
		empty := bytes.NewBuffer([]byte{})
		return empty, empty, empty, empty, err
	}
	caPEM := new(bytes.Buffer)
	if err = pem.Encode(caPEM, &pem.Block{Type: "CERTIFICATE", Bytes: caBytes}); err != nil {
		empty := bytes.NewBuffer([]byte{})
		return empty, empty, empty, empty, err
	}

	caKeyPEM := new(bytes.Buffer)
	if err = pem.Encode(caKeyPEM, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(cakey)}); err != nil {
		empty := bytes.NewBuffer([]byte{})
		return empty, empty, empty, empty, err
	}

	crtPEM := new(bytes.Buffer)
	if err = pem.Encode(crtPEM, &pem.Block{Type: "CERTIFICATE", Bytes: crt}); err != nil {
		empty := bytes.NewBuffer([]byte{})
		return empty, empty, empty, empty, err
	}

	crtKeyPEM := new(bytes.Buffer)
	if err = pem.Encode(crtKeyPEM, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(csrkey)}); err != nil {
		empty := bytes.NewBuffer([]byte{})
		return empty, empty, empty, empty, err
	}

	return caPEM, caKeyPEM, crtPEM, crtKeyPEM, nil
}

// GenerateCA - generate private key and a cert for a CA
func GenerateCA() (*x509.Certificate, *rsa.PrivateKey, error) {
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(123),
		Subject: pkix.Name{
			Organization: []string{"kubearmor"},
			Country:      []string{"US"},
			Province:     []string{""},
			CommonName:   "kubearmor-ca",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(3, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return &x509.Certificate{}, &rsa.PrivateKey{}, errors.New("cannot generate ca private key")
	}

	return ca, caPrivKey, nil
}

// GenerateCSR - generate certificate signing request
func GenerateCSR(namespace string, serviceName string) (*x509.Certificate, *rsa.PrivateKey, error) {
	csr := &x509.Certificate{
		SerialNumber: big.NewInt(1234),
		Subject: pkix.Name{
			Organization: []string{"kubearmor"},
			Country:      []string{"US"},
			Province:     []string{""},
			CommonName:   "kubearmor-webhook",
		},
		DNSNames: []string{
			serviceName + "." + namespace + ".svc",
			serviceName + "." + namespace + ".svc.cluster.local",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(3, 0, 0),
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		SubjectKeyId:          []byte{1, 2, 3, 4, 5},
		BasicConstraintsValid: true,
	}
	certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return &x509.Certificate{}, &rsa.PrivateKey{}, errors.New("cannot generate csr private key")
	}
	return csr, certPrivKey, nil
}

// SignCSR - signs a certificate signing request essentially approving it using the given CA
func SignCSR(caCrt *x509.Certificate, caKey *rsa.PrivateKey, csrCrt *x509.Certificate, csrKey *rsa.PrivateKey) ([]byte, error) {
	certBytes, err := x509.CreateCertificate(rand.Reader, csrCrt, caCrt, &csrKey.PublicKey, caKey)
	if err != nil {
		return []byte{}, errors.New("cannot sign the csr")
	}
	return certBytes, nil
}

// GeneratePkiWithExistingCA generates a new leaf cert signed by an existing CA,
// rather than generating a fresh CA. This is used during TLS rotation to keep
// the CA stable so existing clients don't need to re-trust a new CA.
func GeneratePkiWithExistingCA(namespace string, serviceName string, caCertPEM []byte, caKeyPEM []byte) (*bytes.Buffer, *bytes.Buffer, *bytes.Buffer, error) {
	// Decode and parse the existing CA cert
	caBlock, _ := pem.Decode(caCertPEM)
	if caBlock == nil {
		return bytes.NewBuffer([]byte{}), bytes.NewBuffer([]byte{}), bytes.NewBuffer([]byte{}), errors.New("failed to decode CA cert PEM")
	}
	ca, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return bytes.NewBuffer([]byte{}), bytes.NewBuffer([]byte{}), bytes.NewBuffer([]byte{}), err
	}

	// Decode and parse the existing CA private key
	caKeyBlock, _ := pem.Decode(caKeyPEM)
	if caKeyBlock == nil {
		return bytes.NewBuffer([]byte{}), bytes.NewBuffer([]byte{}), bytes.NewBuffer([]byte{}), errors.New("failed to decode CA key PEM")
	}
	caKey, err := x509.ParsePKCS1PrivateKey(caKeyBlock.Bytes)
	if err != nil {
		return bytes.NewBuffer([]byte{}), bytes.NewBuffer([]byte{}), bytes.NewBuffer([]byte{}), err
	}

	// Generate a new leaf cert signed by the existing CA
	csr, csrKey, err := GenerateCSR(namespace, serviceName)
	if err != nil {
		return bytes.NewBuffer([]byte{}), bytes.NewBuffer([]byte{}), bytes.NewBuffer([]byte{}), err
	}
	crt, err := SignCSR(ca, caKey, csr, csrKey)
	if err != nil {
		return bytes.NewBuffer([]byte{}), bytes.NewBuffer([]byte{}), bytes.NewBuffer([]byte{}), err
	}

	// Re-encode the existing CA cert as PEM (unchanged)
	caPEM := new(bytes.Buffer)
	if err := pem.Encode(caPEM, &pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}); err != nil {
		return bytes.NewBuffer([]byte{}), bytes.NewBuffer([]byte{}), bytes.NewBuffer([]byte{}), err
	}

	crtPEM := new(bytes.Buffer)
	if err := pem.Encode(crtPEM, &pem.Block{Type: "CERTIFICATE", Bytes: crt}); err != nil {
		return bytes.NewBuffer([]byte{}), bytes.NewBuffer([]byte{}), bytes.NewBuffer([]byte{}), err
	}

	crtKeyPEM := new(bytes.Buffer)
	if err := pem.Encode(crtKeyPEM, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(csrKey)}); err != nil {
		return bytes.NewBuffer([]byte{}), bytes.NewBuffer([]byte{}), bytes.NewBuffer([]byte{}), err
	}

	return caPEM, crtPEM, crtKeyPEM, nil
}
