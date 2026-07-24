// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package controllers

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/kubearmor/KubeArmor/pkg/KubeArmorController/types"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrlfake "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

const appArmorTestAnnotation = "container.apparmor.security.beta.kubernetes.io/app"

func TestPodRefresherReconcileTargetsRequestedPod(t *testing.T) {
	ctx := context.Background()
	scheme := podRefreshTestScheme(t)
	pods := podRefreshPods(1000)

	listCalled := false
	k8sClient := ctrlfake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(pods...).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
				listCalled = true
				return c.List(ctx, list, opts...)
			},
		}).
		Build()
	reconciler := podRefreshTestReconciler(k8sClient)

	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKey{
		Namespace: "default",
		Name:      "target",
	}}); err != nil {
		t.Fatalf("Reconcile returned error: %v", err)
	}
	if listCalled {
		t.Fatal("Reconcile listed all pods instead of fetching the requested pod")
	}

	var target corev1.Pod
	if err := k8sClient.Get(ctx, client.ObjectKey{Namespace: "default", Name: "target"}, &target); err != nil {
		t.Fatalf("get target pod: %v", err)
	}
	if got := target.Annotations["kubearmor-policy"]; got != "enabled" {
		t.Fatalf("target kubearmor-policy annotation = %q, want enabled", got)
	}

	var other corev1.Pod
	if err := k8sClient.Get(ctx, client.ObjectKey{Namespace: "default", Name: "pod-999"}, &other); err != nil {
		t.Fatalf("get unrelated pod: %v", err)
	}
	if _, ok := other.Annotations["kubearmor-policy"]; ok {
		t.Fatal("unrelated pod was annotated during targeted reconcile")
	}
}

func BenchmarkPodRefresherReconcileScale(b *testing.B) {
	for _, podCount := range []int{10, 1000} {
		b.Run(fmt.Sprintf("pods_%d", podCount), func(b *testing.B) {
			ctx := context.Background()
			scheme := podRefreshTestScheme(b)
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				k8sClient := ctrlfake.NewClientBuilder().
					WithScheme(scheme).
					WithObjects(podRefreshPods(podCount)...).
					Build()
				reconciler := podRefreshTestReconciler(k8sClient)
				req := ctrl.Request{NamespacedName: client.ObjectKey{
					Namespace: "default",
					Name:      "target",
				}}
				b.StartTimer()

				if _, err := reconciler.Reconcile(ctx, req); err != nil {
					b.Fatalf("Reconcile returned error: %v", err)
				}
			}
		})
	}
}

func podRefreshTestScheme(t testing.TB) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("add corev1 to scheme: %v", err)
	}
	return scheme
}

func podRefreshTestReconciler(k8sClient client.Client) *PodRefresherReconciler {
	return &PodRefresherReconciler{
		Client:    k8sClient,
		ClientSet: fake.NewSimpleClientset(),
		Cluster: &types.Cluster{
			Nodes: map[string]*types.NodeInfo{
				"node-a": {
					KubeArmorActive: true,
				},
			},
			ClusterLock: &sync.RWMutex{},
		},
	}
}

func podRefreshPods(count int) []client.Object {
	pods := make([]client.Object, 0, count+1)
	pods = append(pods, &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "target",
			Annotations: map[string]string{
				appArmorTestAnnotation: "localhost/profile",
			},
		},
		Spec: corev1.PodSpec{
			NodeName:   "node-a",
			Containers: []corev1.Container{{Name: "app", Image: "nginx"}},
		},
	})
	for i := 0; i < count; i++ {
		pods = append(pods, &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "default",
				Name:      fmt.Sprintf("pod-%d", i),
			},
			Spec: corev1.PodSpec{
				NodeName:   "node-a",
				Containers: []corev1.Container{{Name: "app", Image: "nginx"}},
			},
		})
	}
	return pods
}
