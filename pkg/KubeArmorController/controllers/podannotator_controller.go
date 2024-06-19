package controllers

import (
	"context"
	"fmt"
	"strings"

	"github.com/kubearmor/KubeArmor/pkg/KubeArmorController/handlers"
	"github.com/kubearmor/KubeArmor/pkg/KubeArmorOperator/common"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const k8sVisibility = "process,file,network,capabilities"

type PodAnnotateReconciler struct {
	client.Client
}

// +kubebuilder:rbac:groups="",resources=pods,verbs=get;watch;list;create;update;delete
// +kubebuilder:rbac:groups="",resources=nodes,verbs=get;watch;list;create;update;delete
func (r *PodAnnotateReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {

	pod := &corev1.Pod{}
	if err := r.Get(ctx, req.NamespacedName, pod); err != nil {
		if errors.IsNotFound(err) {
			fmt.Println("pod not found  line 30")
			return ctrl.Result{}, nil
		}
		fmt.Println(" error logged line 33")
		return ctrl.Result{}, err
	}
	// Check if NodeName is set
	if pod.Spec.NodeName == "" {
		// Retry after some time if NodeName is not set
		return ctrl.Result{}, nil
	}
	fmt.Println("NodeName found, annotating pod", "NodeName", pod.Spec.NodeName)
	enforcer := r.getEnforcer(pod.Spec.NodeName)

	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {

		// Fetch the latest version of the pod
		if err := r.Get(ctx, req.NamespacedName, pod); err != nil {
			if errors.IsNotFound(err) {
				fmt.Println("Pod not found error line 47")
				return nil // Return nil to stop the retry loop
			}
			fmt.Println("error logged may pod not found  line 50")
			return err
		}
		if pod.Annotations == nil {
			pod.Annotations = make(map[string]string)
		}
		handleAnnotations(pod, enforcer)
		pod.Annotations["node-name"] = pod.Spec.NodeName
		return r.Update(ctx, pod)
	})
	if err != nil {
		fmt.Println("error logged may pod not found  line 61")
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

func (r *PodAnnotateReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Pod{}).
		Complete(r)
}
func handleAnnotations(pod *corev1.Pod, enforcer string) {
	// == Policy == //
	if _, ok := pod.Annotations["kubearmor-policy"]; !ok {
		// if no annotation is set enable kubearmor by default
		pod.Annotations["kubearmor-policy"] = "enabled"
	} else if pod.Annotations["kubearmor-policy"] != "enabled" && pod.Annotations["kubearmor-policy"] != "disabled" && pod.Annotations["kubearmor-policy"] != "audited" {
		// if kubearmor policy is not set correctly, default it to enabled
		pod.Annotations["kubearmor-policy"] = "enabled"
	}

	// == LSM == //

	if enforcer == "AppArmor" {
		handlers.AppArmorAnnotator(pod)
	}

	// == Exception == //

	// exception: kubernetes app
	if pod.Namespace == "kube-system" {
		if _, ok := pod.Labels["k8s-app"]; ok {
			pod.Annotations["kubearmor-policy"] = "audited"
		}

		if value, ok := pod.Labels["component"]; ok {
			if value == "etcd" || value == "kube-apiserver" || value == "kube-controller-manager" || value == "kube-scheduler" {
				pod.Annotations["kubearmor-policy"] = "audited"
			}
		}
	}

	// exception: cilium-operator
	if _, ok := pod.Labels["io.cilium/app"]; ok {
		pod.Annotations["kubearmor-policy"] = "audited"
	}

	// exception: kubearmor
	if _, ok := pod.Labels["kubearmor-app"]; ok {
		pod.Annotations["kubearmor-policy"] = "audited"
	}

	// == Visibility == //

	if _, ok := pod.Annotations["kubearmor-visibility"]; !ok {
		pod.Annotations["kubearmor-visibility"] = k8sVisibility
	}

}
func (r *PodAnnotateReconciler) getEnforcer(nodeName string) string {
	node := &corev1.Node{}
	err := r.Get(context.TODO(), types.NamespacedName{Name: nodeName}, node)
	if err != nil {
		fmt.Println(err, "Failed to get node information")
		return ""
	}

	enforcerLabel, exists := node.Labels[common.EnforcerLabel]
	if !exists {
		fmt.Println("No enforcer label found on the node")
		return ""
	}

	if strings.Contains(enforcerLabel, "bpf") {
		fmt.Println("Detected BPFLSM as the cluster Enforcer")
		return "BPFLSM"
	} else if strings.Contains(enforcerLabel, "apparmor") {
		fmt.Println("Detected AppArmor as the cluster Enforcer")
		return "AppArmor"
	} else if strings.Contains(enforcerLabel, "selinux") {
		fmt.Println("Detected SELinux as the cluster Enforcer")
		return "SELinux"
	}

	fmt.Println("No enforcer was detected")
	return ""
}
