// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package informer

import (
	"context"
	"fmt"
	"strings"

	"github.com/go-logr/logr"
	"github.com/kubearmor/KubeArmor/pkg/KubeArmorController/common"
	"github.com/kubearmor/KubeArmor/pkg/KubeArmorController/types"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

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
	if pod.DeletionTimestamp != nil {
		// pod is being deleted
		return
	}
	if pod.Annotations == nil {
		pod.Annotations = make(map[string]string)
	}

	if pod.OwnerReferences != nil && len(pod.OwnerReferences) != 0 {

		pod.Name = ""
		log.Info(fmt.Sprintf("Restarting pod %s", name))
		err := c.CoreV1().Pods(pod.Namespace).Delete(context.Background(), name, metav1.DeleteOptions{})
		if err != nil {
			log.Info(fmt.Sprintf("Error while deleting pod %s, error=%s", name, err.Error()))
			return
		}

	} else {
		// Delete static pods
		log.Info(fmt.Sprintf("Restarting static pod %s", name))
		err := c.CoreV1().Pods(pod.Namespace).Delete(context.Background(), name, metav1.DeleteOptions{GracePeriodSeconds: new(int64)})
		if err != nil {
			log.Info(fmt.Sprintf("Error while deleting static pod %s, error=%s", name, err.Error()))
			return
		}

	}
	/*
		annotating pods with apparmor annotations beforehand this is
		done due to annotating with mutating webhook can cause a endless loop
	*/
	if apparmor {
		common.AppArmorAnnotator(pod)
	}
	_, err := c.CoreV1().Pods(pod.Namespace).Create(context.Background(), pod, metav1.CreateOptions{})
	if err != nil {
		log.Info(fmt.Sprintf("Error while restarting pod %s, error=%s", name, err.Error()))
		return
	}

	log.Info(fmt.Sprintf("Pod %s has been restarted", name))
}

func HandleAppArmor(annotations map[string]string) bool {
	return !hasApparmorAnnotation(annotations)
}

func HandleBPF(annotations map[string]string) bool {
	return hasApparmorAnnotation(annotations)
}

func IsAppArmorExempt(labels map[string]string, namespace string) bool {

	// exception: kubernetes app
	if namespace == "kube-system" {
		if _, ok := labels["k8s-app"]; ok {
			return true
		}

		if value, ok := labels["component"]; ok {
			if value == "etcd" || value == "kube-apiserver" || value == "kube-controller-manager" || value == "kube-scheduler" || value == "kube-proxy" {
				return true
			}
		}
	}

	// exception: cilium-operator
	if _, ok := labels["io.cilium/app"]; ok {
		return true
	}

	// exception: kubearmor
	if _, ok := labels["kubearmor-app"]; ok {
		return true
	}
	return false
}

func handlePod(c *kubernetes.Clientset, pod *corev1.Pod, enforcer string, log *logr.Logger) {
	if pod.DeletionTimestamp != nil {
		// pod is being deleted
		return
	}
	switch enforcer {
	case "apparmor":

		if HandleAppArmor(pod.Annotations) && !IsAppArmorExempt(pod.Labels, pod.Namespace) {
			restartPod(c, pod, true, log)
		}
		return
	case "bpf":
		if HandleBPF(pod.Annotations) {

			common.RemoveApparmorAnnotation(pod)
			if !IsAppArmorExempt(pod.Labels, pod.Namespace) {
				restartPod(c, pod, false, log)
			}
		}
	default:
		log.Info(fmt.Sprintf("Leaving pod %s as it is, could not determine the enforcer", pod.Name))
	}
}

func PodWatcher(c *kubernetes.Clientset, cluster *types.Cluster, log logr.Logger) {
	log.Info("Starting pod watcher")

	fact := informers.NewSharedInformerFactory(c, 0)
	inf := fact.Core().V1().Pods().Informer()

	inf.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			cluster.ClusterLock.RLock()
			defer cluster.ClusterLock.RUnlock()
			if cluster.HomogeneousStatus {
				return
			}
			if pod, ok := obj.(*corev1.Pod); ok {
				if pod.Spec.NodeName != "" {
					nodeEnforcer := ""
					if _, ok := cluster.Nodes[pod.Spec.NodeName]; ok {
						nodeEnforcer = "apparmor"
					} else {
						nodeEnforcer = "bpf"
					}
					log.Info(fmt.Sprintf("New pod was added, name=%s enforcer=%s", pod.Name, nodeEnforcer))
					handlePod(c, pod, nodeEnforcer, &log)
				}
			}
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			cluster.ClusterLock.RLock()
			defer cluster.ClusterLock.RUnlock()
			if cluster.HomogeneousStatus {
				return
			}
			if pod, ok := newObj.(*corev1.Pod); ok {
				if pod.Spec.NodeName != "" {
					nodeEnforcer := ""
					if _, ok := cluster.Nodes[pod.Spec.NodeName]; ok {
						nodeEnforcer = "apparmor"
					} else {
						nodeEnforcer = "bpf"
					}
					log.Info(fmt.Sprintf("pod was updated, name=%s enforcer=%s", pod.Name, nodeEnforcer))
					handlePod(c, pod, nodeEnforcer, &log)
				}
			}
		},
	})

	inf.Run(wait.NeverStop)
}
