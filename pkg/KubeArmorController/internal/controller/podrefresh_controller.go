// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package controllers

import (
	"context"
	"fmt"
	"time"

	"github.com/kubearmor/KubeArmor/pkg/KubeArmorController/common"
	"github.com/kubearmor/KubeArmor/pkg/KubeArmorController/types"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

type PodRefresherReconciler struct {
	client.Client
	Scheme           *runtime.Scheme
	Cluster          *types.Cluster
	ClientSet        *kubernetes.Clientset
	AnnotateExisting bool
}
type ResourceInfo struct {
	kind          string
	namespaceName string
}

// +kubebuilder:rbac:groups="",resources=pods,verbs=get;watch;list;create;update;delete

func (r *PodRefresherReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {

	log := log.FromContext(ctx)
	var podList corev1.PodList

	if err := r.List(ctx, &podList); err != nil {
		log.Error(err, "Unable to list pods")
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	log.Info("Watching for blocked pods")
	poddeleted := false
	deploymentMap := make(map[string]ResourceInfo)
	for _, pod := range podList.Items {
		if pod.DeletionTimestamp != nil {
			continue
		}
		if pod.Spec.NodeName == "" {
			continue
		}
		r.Cluster.ClusterLock.RLock()
		if _, exist := r.Cluster.Nodes[pod.Spec.NodeName]; exist {
			if !r.Cluster.Nodes[pod.Spec.NodeName].KubeArmorActive {
				log.Info(fmt.Sprintf("skip annotating pod as kubearmor not present on node %s", pod.Spec.NodeName))
				r.Cluster.ClusterLock.RUnlock()
				continue
			}
		}
		enforcer := ""
		if _, ok := r.Cluster.Nodes[pod.Spec.NodeName]; ok {
			enforcer = "apparmor"
		} else {
			enforcer = "bpf"
		}
		r.Cluster.ClusterLock.RUnlock()

		if _, ok := pod.Annotations["kubearmor-policy"]; !ok {
			orginalPod := pod.DeepCopy()
			common.AddCommonAnnotations(&pod.ObjectMeta)
			patch := client.MergeFrom(orginalPod)
			err := r.Patch(ctx, &pod, patch)
			if err != nil {
				if !errors.IsNotFound(err) {
					log.Info(fmt.Sprintf("Failed to patch pod annotations: %s", err.Error()))
				}
			}
		}

		// restart not required for special pods and already annotated pods

		restartPod := requireRestart(pod, enforcer)
		if restartPod {
			// for annotating pre-existing pods on apparmor-nodes
			// the pod is managed by a controller (e.g: replicaset)
			if pod.OwnerReferences != nil && len(pod.OwnerReferences) != 0 {
				// log.Info("Deleting pod " + pod.Name + "in namespace " + pod.Namespace + " as it is managed")
				for _, ref := range pod.OwnerReferences {

					if *ref.Controller {
						if ref.Kind == "ReplicaSet" {
							replicaSet, err := r.ClientSet.AppsV1().ReplicaSets(pod.Namespace).Get(ctx, ref.Name, metav1.GetOptions{})
							if err != nil {
								log.Error(err, fmt.Sprintf("Failed to get ReplicaSet %s:", ref.Name))
								continue
							}
							// Check if the ReplicaSet is managed by a Deployment
							for _, rsOwnerRef := range replicaSet.OwnerReferences {
								if rsOwnerRef.Kind == "Deployment" {
									deploymentName := rsOwnerRef.Name
									deploymentMap[deploymentName] = ResourceInfo{
										kind:          rsOwnerRef.Kind,
										namespaceName: pod.Namespace,
									}
								}
							}
						} else {
							deploymentMap[ref.Name] = ResourceInfo{
								namespaceName: pod.Namespace,
								kind:          ref.Kind,
							}
						}
					}
				}

				// find out deployment--- patch it
				// if err := r.Delete(ctx, &pod); err != nil {
				// 	if !errors.IsNotFound(err) {
				// 		log.Error(err, "Could not delete pod "+pod.Name+" in namespace "+pod.Namespace)
				// 	}
			} else {
				// single pods
				// mimic kubectl replace --force
				// delete the pod --force ==> grace period equals zero
				log.Info("Deleting single pod " + pod.Name + " in namespace " + pod.Namespace)
				if err := r.Delete(ctx, &pod, client.GracePeriodSeconds(0)); err != nil {
					if !errors.IsNotFound(err) {
						log.Error(err, "Could'nt delete pod "+pod.Name+" in namespace "+pod.Namespace)
					}
				}

				// clean the pre-polutated attributes
				pod.ResourceVersion = ""

				// re-create the pod
				if err := r.Create(ctx, &pod); err != nil {
					log.Error(err, "Could not create pod "+pod.Name+" in namespace "+pod.Namespace)
				}
				poddeleted = true
			}

		}
	}

	restartResources(deploymentMap, r.ClientSet)

	// give time for pods to be deleted
	if poddeleted {
		time.Sleep(10 * time.Second)
	}

	return ctrl.Result{}, nil
}

func (r *PodRefresherReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Pod{}).
		Complete(r)
}
func requireRestart(pod corev1.Pod, enforcer string) bool {

	if pod.Namespace == "kube-system" {
		return false
	}
	if _, ok := pod.Labels["io.cilium/app"]; ok {
		return false
	}

	if _, ok := pod.Labels["kubearmor-app"]; ok {
		return false
	}

	// !hasApparmorAnnotations && enforcer == "apparmor"
	if common.HandleAppArmor(pod.Annotations) && enforcer == "apparmor" {
		return true
	}

	return false
}
func restartResources(resourcesMap map[string]ResourceInfo, corev1 *kubernetes.Clientset) error {

	ctx := context.Background()
	log := log.FromContext(ctx)
	for name, resInfo := range resourcesMap {
		switch resInfo.kind {
		case "Deployment":
			dep, err := corev1.AppsV1().Deployments(resInfo.namespaceName).Get(ctx, name, metav1.GetOptions{})
			if err != nil {
				log.Error(err, fmt.Sprintf("error geting deployment %s in namespace %s", name, resInfo.namespaceName))
				continue
			}
			log.Info(fmt.Sprintf("restarting deployment %s in namespace %s", name, resInfo.namespaceName))
			// Update the Pod template's annotations to trigger a rolling restart
			if dep.Spec.Template.Annotations == nil {
				dep.Spec.Template.Annotations = make(map[string]string)
			}
			dep.Spec.Template.Annotations[common.KubeArmorRestartedAnnotation] = time.Now().Format(time.RFC3339)
			// Patch the Deployment
			_, err = corev1.AppsV1().Deployments(resInfo.namespaceName).Update(ctx, dep, metav1.UpdateOptions{})
			if err != nil {
				log.Error(err, fmt.Sprintf("error updating deployment %s in namespace %s", name, resInfo.namespaceName))
			}
		case "Statefulset":
			statefulSet, err := corev1.AppsV1().StatefulSets(resInfo.namespaceName).Get(ctx, name, metav1.GetOptions{})
			if err != nil {
				log.Error(err, fmt.Sprintf("error geting statefulset %s in namespace %s", name, resInfo.namespaceName))
				continue
			}
			log.Info("restarting statefulset " + name + " in namespace " + resInfo.namespaceName)
			// Update the Pod template's annotations to trigger a rolling restart
			if statefulSet.Spec.Template.Annotations == nil {
				statefulSet.Spec.Template.Annotations = make(map[string]string)
			}
			statefulSet.Spec.Template.Annotations[common.KubeArmorRestartedAnnotation] = time.Now().Format(time.RFC3339)
			// Patch the Deployment
			_, err = corev1.AppsV1().StatefulSets(resInfo.namespaceName).Update(ctx, statefulSet, metav1.UpdateOptions{})
			if err != nil {
				log.Error(err, fmt.Sprintf("error updating statefulset %s in namespace %s", name, resInfo.namespaceName))
			}

		case "Daemonset":
			daemonSet, err := corev1.AppsV1().DaemonSets(resInfo.namespaceName).Get(ctx, name, metav1.GetOptions{})
			if err != nil {
				log.Error(err, fmt.Sprintf("error geting daemonset %s in namespace %s", name, resInfo.namespaceName))
				continue
			}
			log.Info("restarting daemonset " + name + " in namespace " + resInfo.namespaceName)
			// Update the Pod template's annotations to trigger a rolling restart
			if daemonSet.Spec.Template.Annotations == nil {
				daemonSet.Spec.Template.Annotations = make(map[string]string)
			}
			daemonSet.Spec.Template.Annotations[common.KubeArmorRestartedAnnotation] = time.Now().Format(time.RFC3339)
			// Patch the Deployment
			_, err = corev1.AppsV1().DaemonSets(resInfo.namespaceName).Update(ctx, daemonSet, metav1.UpdateOptions{})
			if err != nil {
				log.Error(err, fmt.Sprintf("error updating daemonset %s in namespace %s", name, resInfo.namespaceName))
			}
		}
		// wait for few seconds after updating every resource
		time.Sleep(5 * time.Second)
	}

	return nil
}
