// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package informer

import (
	"context"
	"encoding/json"
	"os"
	"strings"

	"github.com/go-logr/logr"
	"github.com/kubearmor/KubeArmor/pkg/KubeArmorController/common"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

const (
	kubeArmorConfigMapName = "kubearmor-config"
	configVisibilityKey    = "visibility"
	namespaceFile          = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
	defaultNamespace       = "kubearmor"
)

// controllerNamespace returns the namespace the controller runs in, which is
// also where the kubearmor-config ConfigMap lives.
func controllerNamespace() string {
	if ns, err := os.ReadFile(namespaceFile); err == nil {
		if name := strings.TrimSpace(string(ns)); name != "" {
			return name
		}
	}
	return defaultNamespace
}

// ConfigWatcher watches the kubearmor-config ConfigMap and keeps the default
// visibility that the webhook sets on pods in sync with its "visibility" value
// (the defaultVisibility of the KubeArmorConfig). When the value changes, pods
// that still have the previous default are patched to the new one.
func ConfigWatcher(c *kubernetes.Clientset, log logr.Logger) {
	log.Info("Starting config watcher")

	fact := informers.NewSharedInformerFactoryWithOptions(c, 0,
		informers.WithNamespace(controllerNamespace()),
		informers.WithTweakListOptions(func(opts *metav1.ListOptions) {
			opts.FieldSelector = fields.OneTermEqualSelector("metadata.name", kubeArmorConfigMapName).String()
		}),
	)
	inf := fact.Core().V1().ConfigMaps().Informer()

	handle := func(obj interface{}) {
		cm, ok := obj.(*corev1.ConfigMap)
		if !ok {
			return
		}
		visibility := strings.TrimSpace(cm.Data[configVisibilityKey])
		if visibility == "" {
			return
		}
		previous := common.SetDefaultVisibility(visibility)
		if previous == visibility {
			return
		}
		log.Info("Default visibility updated", "previous", previous, "visibility", visibility)
		updatePodVisibility(c, previous, visibility, log)
	}

	inf.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: handle,
		UpdateFunc: func(_, newObj interface{}) {
			handle(newObj)
		},
	})

	fact.Start(wait.NeverStop)
}

// updatePodVisibility patches the visibility annotation of pods that still
// have the previous default visibility. Pods with any other value were set
// by the user and are left as they are.
func updatePodVisibility(c kubernetes.Interface, previous, visibility string, log logr.Logger) {
	ctx := context.Background()

	pods, err := c.CoreV1().Pods(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		log.Error(err, "Unable to list pods to update their visibility")
		return
	}

	patch, err := json.Marshal(map[string]interface{}{
		"metadata": map[string]interface{}{
			"annotations": map[string]string{common.VisibilityAnnotation: visibility},
		},
	})
	if err != nil {
		log.Error(err, "Unable to build visibility patch")
		return
	}

	for _, pod := range pods.Items {
		if pod.DeletionTimestamp != nil || pod.Annotations[common.VisibilityAnnotation] != previous {
			continue
		}
		if _, err := c.CoreV1().Pods(pod.Namespace).Patch(ctx, pod.Name, types.MergePatchType, patch, metav1.PatchOptions{}); err != nil {
			log.Error(err, "Unable to update pod visibility", "namespace", pod.Namespace, "pod", pod.Name)
		}
	}
}
