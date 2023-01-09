// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package informer

import (
	"context"
	"strings"

	"github.com/go-logr/logr"
	"github.com/kubearmor/KubeArmor/pkg/KubeArmorController/handlers"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	v1 "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
)

type MultiEnforcerController struct {
	Client    kubernetes.Clientset
	Log       logr.Logger
	Cluster   Cluster
	PodLister v1.PodLister
}

func hasApparmorAnnotation(annotations map[string]string) bool {
	for key := range annotations {
		if strings.HasPrefix(key, "container.apparmor.security.beta.kubernetes.io/") {
			return true
		}
	}
	return false
}

func restartPod(c *kubernetes.Clientset, pod *corev1.Pod, apparmor bool, log *logr.Logger) {
	name := pod.Name
	pod.ResourceVersion = ""
	pod.UID = ""
	log.Info("Restarting pod %s", name)
	if pod.Annotations == nil {
		pod.Annotations = make(map[string]string)
	}
	pod.Annotations[handlers.KubeArmorRestartedAnnotation] = "true"
	if apparmor {
		pod.Annotations[handlers.KubeArmorForceAppArmorAnnotation] = "true"
	}
	if pod.OwnerReferences != nil && len(pod.OwnerReferences) != 0 {
		pod.Name = ""
	}
	err := c.CoreV1().Pods(pod.Namespace).Delete(context.Background(), name, metav1.DeleteOptions{})
	if err != nil {
		log.Error(err, "Error while deleting pod %s", name)
	} else {
		_, err = c.CoreV1().Pods(pod.Namespace).Create(context.Background(), pod, metav1.CreateOptions{})
		if err != nil {
			log.Error(err, "Error while restarting pod %s", name)
		}
	}
	log.Info("Pod %s has been restarted")
}

func handleAppArmor(annotations map[string]string) bool {
	return !hasApparmorAnnotation(annotations)
}

func handleBPF(annotations map[string]string) bool {
	return hasApparmorAnnotation(annotations)
}

func handlePod(c *kubernetes.Clientset, pod *corev1.Pod, enforcer string, log *logr.Logger) {
	switch enforcer {
	case "apparmor":
		if handleAppArmor(pod.Annotations) {
			restartPod(c, pod, true, log)
		}
		return
	case "bpf":
		if handleBPF(pod.Annotations) {
			annotations := []string{}

			for key := range pod.Annotations {
				if strings.HasPrefix(key, "container.apparmor.security.beta.kubernetes.io/") {
					annotations = append(annotations, key)
				}
			}

			for _, key := range annotations {
				delete(pod.Annotations, key)
			}

			restartPod(c, pod, false, log)
		}
	default:
		log.Info("Leaving pod %s as it is, couldnot determin the enforcer", pod.Name)
	}
}

func PodWatcher(c *kubernetes.Clientset, cluster *Cluster, log logr.Logger) {
	log.Info("Starting pod watcher")

	fact := informers.NewSharedInformerFactory(c, 0)
	inf := fact.Core().V1().Pods().Informer()

	inf.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			cluster.ClusterLock.Lock()
			defer cluster.ClusterLock.Unlock()
			if cluster.HomogeneousStatus {
				return
			}
			if pod, ok := obj.(*corev1.Pod); ok {
				if pod.Spec.NodeName != "" {
					handlePod(c, pod, cluster.Nodes[pod.Spec.NodeName], &log)
				}
			}
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			cluster.ClusterLock.Lock()
			defer cluster.ClusterLock.Unlock()
			if cluster.HomogeneousStatus {
				return
			}
			if pod, ok := newObj.(*corev1.Pod); ok {
				if pod.Spec.NodeName != "" {
					handlePod(c, pod, cluster.Nodes[pod.Spec.NodeName], &log)
				}
			}
		},
	})

	inf.Run(wait.NeverStop)
}
