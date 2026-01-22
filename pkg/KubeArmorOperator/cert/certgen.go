// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

// Package cert is responsible for generating client and server certificates using KubeArmor cert pkg.
package cert

import (
	"fmt"
	"time"

	certutil "github.com/kubearmor/KubeArmor/KubeArmor/cert"
	"github.com/kubearmor/KubeArmor/pkg/KubeArmorOperator/common"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"
)

var CACert *certutil.CertKeyPair

func GetRelayServiceDnsName(namespace string) []string {
	res := []string{
		fmt.Sprintf("kubearmor.%s", namespace),
		fmt.Sprintf("kubearmor.%s.svc", namespace),
		fmt.Sprintf("kubearmor.%s.svc.cluster.local", namespace),
	}
	return res
}

func GenerateKubeArmorCACert() (certutil.CertBytes, error) {
	caCertConfig := certutil.DefaultKubeArmorCAConfig
	caCertConfig.NotAfter = time.Now().AddDate(1, 0, 0) // valid for one year
	crtBytes, err := certutil.GenerateCA(&caCertConfig)
	if err != nil {
		klog.Errorf("error generating ca cert: %s", err)
		return certutil.CertBytes{}, err
	}
	crtKeyPair, err := certutil.GetCertKeyPairFromCertBytes(crtBytes)
	if err != nil {
		return certutil.CertBytes{}, err
	}
	CACert = crtKeyPair
	return *crtBytes, nil
}

func GenerateKubeArmorClientCert() (certutil.CertBytes, error) {
	if CACert == nil {
		_, err := GenerateKubeArmorCACert()
		if err != nil {
			return certutil.CertBytes{}, err
		}
	}
	certCfg := certutil.DefaultKubeArmorClientConfig
	certCfg.NotAfter = time.Now().AddDate(1, 0, 0)
	crtBytes, err := certutil.GenerateSelfSignedCert(CACert, &certCfg)
	if err != nil {
		klog.Errorf("error generating kubearmor client cert: %s", err)
		return certutil.CertBytes{}, err
	}
	return *crtBytes, nil
}

func GenerateKubeArmorRelayCert() (certutil.CertBytes, error) {
	if CACert == nil {
		_, err := GenerateKubeArmorCACert()
		if err != nil {
			return certutil.CertBytes{}, err
		}
	}
	certCfg := certutil.DefaultKubeArmorServerConfig
	certCfg.NotAfter = time.Now().AddDate(1, 0, 0)
	dnsList := GetRelayServiceDnsName(common.Namespace)
	dnsList = append(dnsList, common.ExtraDnsNames...)
	certCfg.DNS = append(certCfg.DNS, dnsList...)
	certCfg.IPs = append(certCfg.IPs, common.ExtraIpAddresses...)
	klog.Infof("relay cert extUsage: %v", certCfg.ExtKeyUsage)
	crtBytes, err := certutil.GenerateSelfSignedCert(CACert, &certCfg)
	if err != nil {
		klog.Errorf("error generating kubearmor relay cert: %s", err)
		return certutil.CertBytes{}, err
	}
	return *crtBytes, nil
}

func GetCertSecret(crt *[]byte, key *[]byte, name, namespace string, labels *map[string]string) *corev1.Secret {

	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    *labels,
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			"tls.crt": *crt,
			"tls.key": *key,
		},
	}
}

func GetCertWithCaSecret(ca, crt, key *[]byte, name, namespace string, labels *map[string]string) *corev1.Secret {

	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    *labels,
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			"tls.crt": *crt,
			"tls.key": *key,
			"ca.crt":  *ca,
		},
	}

}

func GetAllTlsCertSecrets() ([]*corev1.Secret, error) {
	fmt.Println("Prepairing all the tls secrets")
	secrets := []*corev1.Secret{}
	var certGenErr, err error
	var kaCaCert, kaClientCert, kaRelayCert certutil.CertBytes
	for i := 0; i < 3; i++ {
		// generate kubearmor-ca certs
		kaCaCert, err = GenerateKubeArmorCACert()
		if err != nil {
			certGenErr = err
		}
		// generate kubearmor-client certs
		kaClientCert, err = GenerateKubeArmorClientCert()
		if err != nil {
			certGenErr = err
		}
		// generate kubearmor-relay certs
		kaRelayCert, err = GenerateKubeArmorRelayCert()
		if err != nil {
			certGenErr = err
		}
		if certGenErr == nil {
			break
		}
		time.Sleep(3 * time.Second)
	}
	if certGenErr != nil {
		return secrets, certGenErr
	} else {
		// create secrets
		secrets = append(secrets,
			GetCertSecret(&kaCaCert.Crt, &kaCaCert.Key, common.KubeArmorCaSecretName, common.Namespace, &map[string]string{"kubearmor-app": common.KubeArmorCaSecretName}),
			GetCertWithCaSecret(&kaCaCert.Crt, &kaClientCert.Crt, &kaClientCert.Key, common.KubeArmorClientSecretName, common.Namespace, &map[string]string{"kubearmor-app": common.KubeArmorClientSecretName}),
			GetCertWithCaSecret(&kaCaCert.Crt, &kaRelayCert.Crt, &kaRelayCert.Key, common.KubeArmorRelayServerSecretName, common.Namespace, &map[string]string{"kubearmor-app": common.KubeArmorRelayServerSecretName}))
	}
	return secrets, nil
}
