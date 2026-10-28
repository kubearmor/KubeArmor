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
func GeneratePki(namespace string, serviceName string) (caPEM, caKeyPEM, crtPEM, crtKeyPEM *bytes.Buffer, err error) {
	ca, cakey, err := GenerateCA()
	if err != nil {
		return nil, nil, nil, nil, err
	}
	csr, csrkey, err := GenerateCSR(namespace, serviceName)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	crt, err := SignCSR(ca, cakey, csr, csrkey)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &cakey.PublicKey, cakey)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	caPEM = new(bytes.Buffer)
	err = pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})
	if err != nil {
		return nil, nil, nil, nil, err
	}

	caKeyPEM = new(bytes.Buffer)
	err = pem.Encode(caKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(cakey),
	})
	if err != nil {
		return nil, nil, nil, nil, err
	}

	crtPEM = new(bytes.Buffer)
	err = pem.Encode(crtPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: crt,
	})
	if err != nil {
		return nil, nil, nil, nil, err
	}
	crtKeyPEM = new(bytes.Buffer)
	err = pem.Encode(crtKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(csrkey),
	})
	if err != nil {
		return nil, nil, nil, nil, err
	}
	return caPEM, caKeyPEM, crtPEM, crtKeyPEM, nil
}

// GeneratePkiWithCA - generate leaf keypair signed by the given CA cert and CA key
func GeneratePkiWithCA(namespace string, serviceName string, caPEM []byte, caKeyPEM []byte) (caCert, crtPEM, crtKeyPEM *bytes.Buffer, err error) {
	// Parse CA Cert PEM
	block, _ := pem.Decode(caPEM)
	if block == nil {
		return nil, nil, nil, errors.New("failed to decode CA certificate PEM")
	}
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, nil, err
	}

	// Parse CA Key PEM
	keyBlock, _ := pem.Decode(caKeyPEM)
	if keyBlock == nil {
		return nil, nil, nil, errors.New("failed to decode CA key PEM")
	}
	caKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, nil, err
	}

	csr, csrkey, err := GenerateCSR(namespace, serviceName)
	if err != nil {
		return nil, nil, nil, err
	}
	crt, err := SignCSR(ca, caKey, csr, csrkey)
	if err != nil {
		return nil, nil, nil, err
	}

	crtPEM = new(bytes.Buffer)
	err = pem.Encode(crtPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: crt,
	})
	if err != nil {
		return nil, nil, nil, err
	}
	crtKeyPEM = new(bytes.Buffer)
	err = pem.Encode(crtKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(csrkey),
	})
	if err != nil {
		return nil, nil, nil, err
	}

	return bytes.NewBuffer(caPEM), crtPEM, crtKeyPEM, nil
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
