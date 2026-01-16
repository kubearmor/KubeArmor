// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

// Package cert is responsible for generating certs dynamically and loading the certs from external sources.
package cert

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"

	"k8s.io/client-go/kubernetes"
)

type CertLoader interface {
	GetCertificateAndCaPool() (*tls.Certificate, *x509.CertPool, error)
}

// generate self sign certificate dynamically
type SelfSignedCertLoader struct {
	CaCertPath CertPath
	CertConfig CertConfig
}

func (loader *SelfSignedCertLoader) GetCertificateAndCaPool() (*tls.Certificate, *x509.CertPool, error) {
	// load ca certificate and ca key from given path
	caCertBytes, err := ReadCertFromFile(&loader.CaCertPath)
	if err != nil {
		return nil, nil, err
	}
	caCert, err := GetCertKeyPairFromCertBytes(caCertBytes)
	if err != nil {
		return nil, nil, err
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AddCert(caCert.Crt)
	// create certificate signed with provided ca certificate
	certBytes, err := GenerateSelfSignedCert(caCert, &loader.CertConfig)
	if err != nil {
		return nil, nil, err
	}
	cert, err := tls.X509KeyPair(certBytes.Crt, certBytes.Key)
	if err != nil {
		return nil, nil, err
	}
	return &cert, caCertPool, nil
}

// load certificates provided by external source using file
type ExternalCertLoader struct {
	CaCertPath CertPath
	CertPath   CertPath
}

func (loader *ExternalCertLoader) GetCertificateAndCaPool() (*tls.Certificate, *x509.CertPool, error) {
	// load ca certificate from cert path, assuming only ca.crt is present
	loader.CaCertPath.CertOnly = true
	caCertBytes, err := ReadCertFromFile(&loader.CaCertPath)
	if err != nil {
		return nil, nil, err
	}
	caCertPem, _ := pem.Decode(caCertBytes.Crt)
	caCert, err := x509.ParseCertificate(caCertPem.Bytes)
	if err != nil {
		return nil, nil, err
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AddCert(caCert)
	// load server/client certificate from cert path
	certBytes, err := ReadCertFromFile(&loader.CertPath)
	if err != nil {
		return nil, nil, err
	}
	cert, err := tls.X509KeyPair(certBytes.Crt, certBytes.Key)
	if err != nil {
		return nil, nil, err
	}
	return &cert, caCertPool, nil
}

type K8sCertLoader struct {
	CertConfig CertConfig
	K8sClient  *kubernetes.Clientset
	Namespace  string
	Secret     string
}

func (loader *K8sCertLoader) GetCertificateAndCaPool() (*tls.Certificate, *x509.CertPool, error) {
	// load certificate from k8s secret
	caCertBytes, err := ReadCertFromK8sSecret(loader.K8sClient, loader.Namespace, loader.Secret)
	if err != nil {
		return nil, nil, err
	}
	caCert, err := GetCertKeyPairFromCertBytes(caCertBytes)
	if err != nil {
		return nil, nil, err
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AddCert(caCert.Crt)
	// create certificate signed with provided ca certificate
	certBytes, err := GenerateSelfSignedCert(caCert, &loader.CertConfig)
	if err != nil {
		return nil, nil, err
	}
	cert, err := tls.X509KeyPair(certBytes.Crt, certBytes.Key)
	if err != nil {
		return nil, nil, err
	}
	return &cert, caCertPool, nil
}
