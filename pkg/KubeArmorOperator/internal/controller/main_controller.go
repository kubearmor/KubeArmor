// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package controller

import (
	"context"
	"os"
	"time"

	operatorv1 "github.com/kubearmor/KubeArmor/pkg/KubeArmorOperator/api/operator.kubearmor.com/v1"
	embedFs "github.com/kubearmor/KubeArmor/pkg/KubeArmorOperator/embed"
	"github.com/kubearmor/KubeArmor/pkg/KubeArmorOperator/internal/helm"
	"go.uber.org/zap"
	extv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	extv1clientset "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	// "k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	// "k8s.io/apimachinery/pkg/runtime/schema"
	// "k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/yaml"
)

// OperatorConfig injects operator configurations
type OperatorConfig struct {
	// enable rollback if release upgrade failed
	RollbackOnFailure bool
	// kubearmor chart version to install
	Version string
	// kubearmor chart repository
	Repository string
	// chart directory if local chart
	Directory string
	// chart name or chartRef
	ChartName string
	// namespace to deploy chart
	Namespace string
	// Snitch path prefix
	SnitchPathPrefix string
	// Snitch image
	SnitchImage string
	// Snitch imagePullPolicy
	SnitchImagePullPolicy string
	// Lsm preference order
	LsmOrder string
	// skip install operator CRD
	SkipCRD bool
	// Conversion Webhook service
	WebhookService string
	// Operator deployment name
	OperatorDeploymentName string
	// operator deployment uid
	OperatorDeploymentUID string
}

// Operator repesents operator implementation
type Operator struct {
	namespace                 string
	webhookService            string
	skipcrd                   bool
	k8sClient                 client.Client
	k8sClientSet              *kubernetes.Clientset
	log                       *zap.SugaredLogger
	clusterWatcher            *ClusterWatcher
	helmInstaller             *helm.Controller
	kubeArmorConfigReconciler *KubeArmorConfigReconciler
	controllerManager         ctrl.Manager
}

// NewOperator initializes and returns an operator instance
func NewOperator(cfg OperatorConfig, k8sClient client.Client, k8sClientSet *kubernetes.Clientset, manager ctrl.Manager) (*Operator, error) {
	logger, _ := zap.NewProduction()
	log := logger.With(zap.String("component", "operator")).Sugar()

	log.Infof("operator has been configured %+v", cfg)

	// helm controller
	helmConfig := helm.Config{
		ChartName:         cfg.ChartName,
		Namespace:         cfg.Namespace,
		Version:           cfg.Version,
		Repository:        cfg.Repository,
		Directory:         cfg.Directory,
		RollbackOnFailure: cfg.RollbackOnFailure,
	}

	helmController, err := helm.NewHelmController(helmConfig)
	if err != nil {
		return nil, err
	}

	// cluster watcher
	watcherConfig := WatcherConfig{
		SnitchImage:              cfg.SnitchImage,
		SnitchPathPrefix:         cfg.SnitchPathPrefix,
		SnitchImagePullPolicy:    cfg.SnitchImagePullPolicy,
		LsmOrder:                 cfg.LsmOrder,
		OperatorWatchedNamespace: cfg.Namespace,
		OperatorDeploymentName:   cfg.OperatorDeploymentName,
		OperatorDeploymentUID:    cfg.OperatorDeploymentUID,
	}

	clusterWatcher, err := NewClusterWatcher(watcherConfig, k8sClientSet, helmController)
	if err != nil {
		return nil, err
	}
	kubeArmorConfigReconciler := KubeArmorConfigReconciler{
		helmController,
		k8sClient,
		k8sClient.Scheme(),
	}

	return &Operator{
		namespace:                 cfg.Namespace,
		webhookService:            cfg.WebhookService,
		skipcrd:                   cfg.SkipCRD,
		k8sClient:                 k8sClient,
		k8sClientSet:              k8sClientSet,
		log:                       log,
		clusterWatcher:            clusterWatcher,
		helmInstaller:             helmController,
		kubeArmorConfigReconciler: &kubeArmorConfigReconciler,
		controllerManager:         manager,
	}, nil
}

func (operator *Operator) installCRD() error {

	crdYaml, err := embedFs.CRDFs.ReadFile("operator.kubearmor.com_kubearmorconfigs.yaml")
	if err != nil {
		operator.log.Fatalf("error reading crd yaml manifest: %s", err.Error())
	}
	// crdGVR := schema.GroupVersionResource{
	// 	Group:    "apiextensions.k8s.io",
	// 	Version:  "v1",
	// 	Resource: "customresourcedefinitions",
	// }
	// crdGVK := schema.GroupVersionKind{
	// 	Group:   "apiextensions.k8s.io",
	// 	Version: "v1",
	// 	Kind:    "CustomResourceDefinition",
	// }
	crdObjectExtv1 := &extv1.CustomResourceDefinition{}
	err = yaml.Unmarshal(crdYaml, crdObjectExtv1)
	if err != nil {
		operator.log.Fatalf("error unmarshalling yaml as CRD object: %s", err.Error())
	}
	// sec, err := operator.k8sClientSet.CoreV1().Secrets("NAMESPACE").Get(context.TODO(), "SECRET_NAME", metav1.GetOptions{})
	// if err != nil {
	// 	log.Fatalf("error getting ca secret: %s", err.Error())
	// }
	caBundle, err := os.ReadFile("/tmp/k8s-webhook-server/serving-certs/ca.crt")
	if err != nil {
		operator.log.Fatalf("error reading ca.crt from mounted fs: %s", err.Error())
	}
	webhookPath := "/convert"
	crdObjectExtv1.Spec.Conversion = &extv1.CustomResourceConversion{
		Strategy: extv1.ConversionStrategyType("Webhook"),
		Webhook: &extv1.WebhookConversion{
			ClientConfig: &extv1.WebhookClientConfig{
				Service: &extv1.ServiceReference{
					Namespace: operator.namespace,
					Name:      operator.webhookService,
					Path:      &webhookPath,
				},
				CABundle: caBundle,
			},
			ConversionReviewVersions: []string{"v1"},
		},
	}
	// crdObject, err := yaml.YAMLToJSON(crdYaml)
	// if err != nil {
	// 	log.Fatalf("error converting yaml to json: %s", err.Error())
	// }
	// u := &unstructured.Unstructured{}
	// _, _, err = unstructured.UnstructuredJSONScheme.Decode(crdObject, &crdGVK, u)
	// if err != nil {
	// 	log.Fatalf("error decoding crd yaml as runtime object: %s", err.Error())
	// }
	// webhookPatch := map[string]interface{}{
	// 	"strategy": "Webhook",
	// 	"webhook": map[string]interface{}{
	// 		"clientConfig": map[string]interface{}{
	// 			"service": map[string]interface{}{
	// 				"namespace": os.Getenv(""),
	// 				"name":      "kubearmor-operator-webhook-service",
	// 				"path":      "/convert",
	// 			},
	// 			"caBundle": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUR0ekNDQXArZ0F3SUJBZ0lVU3c0R1BjVFRUU3dnd2ozZzZHdXlQZHEyVFAwd0RRWUpLb1pJaHZjTkFRRUwKQlFBd2F6RUxNQWtHQTFVRUJoTUNWVk14RGpBTUJnTlZCQWdNQlZOMFlYUmxNUTB3Q3dZRFZRUUhEQVJEYVhSNQpNUlV3RXdZRFZRUUtEQXhQY21kaGJtbDZZWFJwYjI0eEVEQU9CZ05WQkFzTUIwOXlaMVZ1YVhReEZEQVNCZ05WCkJBTU1DMlY0WVcxd2JHVXVZMjl0TUI0WERUSTBNRGN4TnpBNE5EY3lNRm9YRFRJMU1EY3hOekE0TkRjeU1Gb3cKYXpFTE1Ba0dBMVVFQmhNQ1ZWTXhEakFNQmdOVkJBZ01CVk4wWVhSbE1RMHdDd1lEVlFRSERBUkRhWFI1TVJVdwpFd1lEVlFRS0RBeFBjbWRoYm1sNllYUnBiMjR4RURBT0JnTlZCQXNNQjA5eVoxVnVhWFF4RkRBU0JnTlZCQU1NCkMyVjRZVzF3YkdVdVkyOXRNSUlCSWpBTkJna3Foa2lHOXcwQkFRRUZBQU9DQVE4QU1JSUJDZ0tDQVFFQW8veGQKVEMwTE9DOVNpYTVXNmdvamRaTFZsSEhNNHZ6OW92WUdQMzlscFVpSGRpbDgrK1EyMHlzaHdodnZ3VlFPZklFcgpUT3Y5U2FVa2xUUCticHNPYjZYMjNlcThJamF5bWU2eDhVc2h1TUpBeGdGK1dpbGdINk92TlppajNyWlNRdUg0CndQSUw3WFZLZ3NkK2NKVUljMlZrRFFBRFQrbEc1VkcxRE9seTc1UVA3Tk8yMHZvVHU4Nkx2RGh4eG1pZVhPZjkKS2I2SE9MOTdoYjlydExKNzdmeWNIT2FYaFd4ZUZzM291QWtvbncyQWdwendWc3M1Z2UzaUU0c2lVREwraVN2dQpadHc3c2Y3QnI2Q1JJMVRzdjJqd0JMTlpZMG8veUphOHBxVWpENzN6M1NMeDVsZHhla1RlOE56TG9GV0F3eGZGCjhNMWlYNnlxQWxXcjhOV0JKUUlEQVFBQm8xTXdVVEFkQmdOVkhRNEVGZ1FVN1l2c2dMQ0wzdzEwU0Vvb2U5LzAKK0FaWmYyc3dId1lEVlIwakJCZ3dGb0FVN1l2c2dMQ0wzdzEwU0Vvb2U5LzArQVpaZjJzd0R3WURWUjBUQVFILwpCQVV3QXdFQi96QU5CZ2txaGtpRzl3MEJBUXNGQUFPQ0FRRUFDTGExcmRUcmJmZ0RFQ2p6czVBWG0zOEpUcGFTClp2TG43dEJTR1NqT1NncWFla3JCbU1Ka0VWY0FjUnBFbzkyT3lTMVVLWmUrU3N6V1dENzRSeHcxTlpBc2dVVHQKK09RbGVyQ1ZNU0ZHVytyTnFkck1tdThobEUxeER5UEpoNzRKNWdZbHpJN3c3b0dXZHRXMXRNZDdKQTVGQVNXZgpOd3dVeG1KWlRvQjdmQ0hhd1JBM24rZjIzUFo3dXF1TFVhWHpldVczbGJzOUNBQW1GeEhaaGdDRThYQ1U1RWhUCk1tSk1xY2VEZGpVM3hnOU9RczlLY2dRSGtVN0YyZy9CUmJOVG5xZTFWQ0NkbHp5MlVrb0FDTi9SRitlSTBUMlAKczI1UUFSc0ZIbWkxeXluRnc4aVF5VFlFMkZaWWRJL2dSWGZmY2I1aDE0OG9IT0hrbFIrdlVyTENsUT09Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K",
	// 		},
	// 		"conversionReviewVersions": []interface{}{"v1"},
	// 	},
	// }
	// unstructured.SetNestedField(u.Object, webhookPatch, "spec", "conversion")

	config := ctrl.GetConfigOrDie()
	// dynamicClient, err := dynamic.NewForConfig(config)
	// if err != nil {
	// 	log.Fatalf("error initializing dynamic client: %s", err.Error())
	// }
	// _, err = dynamicClient.Resource(crdGVR).Apply(context.TODO(), u.GetName(), u, metav1.ApplyOptions{FieldManager: "kubearmor-operator"})

	extv1Client, err := extv1clientset.NewForConfig(config)
	_, err = extv1Client.ApiextensionsV1().CustomResourceDefinitions().Get(context.TODO(), crdObjectExtv1.GetName(), metav1.GetOptions{})
	if err != nil {
		if !errors.IsNotFound(err) {
			operator.log.Fatalf("cannot get operator.kubearmor.com_kubearmorconfig crd status: %s", err.Error())
		}
		_, err := extv1Client.ApiextensionsV1().CustomResourceDefinitions().Create(context.TODO(), crdObjectExtv1, metav1.CreateOptions{})
		if err != nil {
			operator.log.Fatalf("error creating operator.kubearmor.com_kubearmorconfig crd: %s", err.Error())
		}
		operator.log.Infoln("successfully created operator.kubearmor.com_kubearmorconfig crd")
		return nil
	}
	if err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
		crd, err := extv1Client.ApiextensionsV1().CustomResourceDefinitions().Get(context.TODO(), crdObjectExtv1.GetName(), metav1.GetOptions{})
		crd.Spec = crdObjectExtv1.Spec
		_, err = extv1Client.ApiextensionsV1().CustomResourceDefinitions().Update(context.TODO(), crd, metav1.UpdateOptions{})
		return err
	}); err != nil {
		operator.log.Fatalf("error updating operator.kubearmor.com_kubearmorconfig crd: %s", err.Error())
	}

	return err
}

// Start runs operator componenets
func (operator *Operator) Start() {

	err := operator.helmInstaller.Preinstall()
	if err != nil {
		operator.log.Errorf("error while cleaning up existing release", err.Error())
	}

	if !operator.skipcrd {
		err = operator.installCRD()
		if err != nil {
			operator.log.Fatalf("error applying operator.kubearmor.com_kubearmorconfig CRD: %s", err.Error())
		}
		// This sleep could help avoiding any potential issue due to some ms delay in CRD registration
		time.Sleep(1 * time.Second)
	}

	// start cluster(node)watcher
	go operator.clusterWatcher.WatchNodes()

	// start v1 conversion webhook
	if err = (&operatorv1.KubeArmorConfig{}).SetupWebhookWithManager(operator.controllerManager); err != nil {
		operator.log.Error(err, "unable to setup conversion webhook", "webhook", "KubeArmorConfig")
		os.Exit(1)
	}

	// start kubeconfigreconciler
	if err = operator.kubeArmorConfigReconciler.SetupWithManager(operator.controllerManager); err != nil {
		operator.log.Error(err, "unable to create controller", "controller", "KubeArmorConfig")
		os.Exit(1)
	}
	//+kubebuilder:scaffold:builder

	if err := operator.controllerManager.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		operator.log.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := operator.controllerManager.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		operator.log.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	operator.log.Info("starting manager")
	if err := operator.controllerManager.Start(ctrl.SetupSignalHandler()); err != nil {
		operator.log.Error(err, "problem running manager")
		os.Exit(1)
	}
}
