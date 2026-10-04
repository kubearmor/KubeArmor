// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package cmd

import (
	opclient "github.com/kubearmor/KubeArmor/pkg/KubeArmorOperator/client/clientset/versioned"
	"go.uber.org/zap"
	apiextensionsclientset "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	"k8s.io/client-go/kubernetes"
)

type OperatorOptions struct {
	K8sClient                          *kubernetes.Clientset
	Logger                             *zap.SugaredLogger
	KubeConfig                         string
	Context                            string
	LsmOrder                           string
	PathPrefix                         string
	DeploymentName                     string
	ExtClient                          *apiextensionsclientset.Clientset
	Opv1Client                         *opclient.Clientset
	Secv1Client                        *opclient.Clientset
	AnnotateResource                   bool
	AnnotateExisting                   bool
	InitDeploy                         bool
	LogLevel                           string
	ProviderHostname, ProviderEndpoint string
	ImagePullSecrets                   []string
	SocketFile                         string

	MetricsAddr          string
	EnableLeaderElection bool
	ProbeAddr            string
	SecureMetrics        bool
	EnableHTTP2          bool
	WebhookPort          int
}

type SnitchOptions struct {
	KubeConfig string
	Context    string
	LsmOrder   string

	NodeName       string
	Runtime        string
	EnableOCIHooks bool
	LogLevel       string
}
