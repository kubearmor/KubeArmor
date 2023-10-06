// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package k8s

import (
	"os"

	opv1client "github.com/kubearmor/KubeArmor/pkg/KubeArmorOperator/client/clientset/versioned"
	"go.uber.org/zap"
	apiextensionsclientset "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	"k8s.io/client-go/kubernetes"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

func NewClient(log zap.SugaredLogger, kubeconfig string) *kubernetes.Clientset {
	var cfg *rest.Config
	log.Info("Trying to load InCluster configuration")
	inClusterConfig, err := rest.InClusterConfig()
	if err == rest.ErrNotInCluster {
		log.Info("Not inside a k8s Cluster, Loading kubeconfig")
		kubeConfig, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
			&clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfig},
			&clientcmd.ConfigOverrides{}).ClientConfig()
		if err != nil {
			log.Errorf("Couldn't load configuration from kubeconfig Error=%s", err.Error())
			os.Exit(1)
		}
		log.Info("Loaded configuration from kubeconfig")
		cfg = kubeConfig
	} else if err != nil {
		log.Errorf("Couldn't load inCluster configuration Error=%s", err.Error())
		os.Exit(1)

	} else {
		log.Info("Loaded InCluster configuration")
		cfg = inClusterConfig
	}

	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		log.Errorf("Couldn't create k8s clientset Error=%s", err.Error())
		os.Exit(1)
	}

	return client
}

func NewExtClient(log zap.SugaredLogger, kubeconfig string) *apiextensionsclientset.Clientset {
	var cfg *rest.Config
	log.Info("Trying to load InCluster configuration")
	inClusterConfig, err := rest.InClusterConfig()
	if err == rest.ErrNotInCluster {
		log.Info("Not inside a k8s Cluster, Loading kubeconfig")
		kubeConfig, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
			&clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfig},
			&clientcmd.ConfigOverrides{}).ClientConfig()
		if err != nil {
			log.Errorf("Couldn't load configuration from kubeconfig Error=%s", err.Error())
			os.Exit(1)
		}
		log.Info("Loaded configuration from kubeconfig")
		cfg = kubeConfig
	} else if err != nil {
		log.Errorf("Couldn't load inCluster configuration Error=%s", err.Error())
		os.Exit(1)

	} else {
		log.Info("Loaded InCluster configuration")
		cfg = inClusterConfig
	}

	client, err := apiextensionsclientset.NewForConfig(cfg)
	if err != nil {
		log.Errorf("Couldn't create k8s extensions clientset Error=%s", err.Error())
		os.Exit(1)
	}

	return client
}

func NewOpv1Client(log zap.SugaredLogger, kubeconfig string) *opv1client.Clientset {
	var cfg *rest.Config
	log.Info("Trying to load InCluster configuration")
	inClusterConfig, err := rest.InClusterConfig()
	if err == rest.ErrNotInCluster {
		log.Info("Not inside a k8s Cluster, Loading kubeconfig")
		kubeConfig, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
			&clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfig},
			&clientcmd.ConfigOverrides{}).ClientConfig()
		if err != nil {
			log.Errorf("Couldn't load configuration from kubeconfig Error=%s", err.Error())
			os.Exit(1)
		}
		log.Info("Loaded configuration from kubeconfig")
		cfg = kubeConfig
	} else if err != nil {
		log.Errorf("Couldn't load inCluster configuration Error=%s", err.Error())
		os.Exit(1)

	} else {
		log.Info("Loaded InCluster configuration")
		cfg = inClusterConfig
	}

	client, err := opv1client.NewForConfig(cfg)
	if err != nil {
		log.Errorf("Couldn't create operatorv1 clientset Error=%s", err.Error())
		os.Exit(1)
	}

	if client == nil {
		log.Warn("opv1client is nil")
	}

	return client
}
