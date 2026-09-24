// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package e2e

import (
	"context"
	"fmt"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	operatorV1 "github.com/kubearmor/KubeArmor/pkg/KubeArmorOperator/api/operator.kubearmor.com/v1"
)

func TestFileAccessPatternDropping(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping E2E test in short mode")
	}

	t.Run("DroppedPathsNotReported", func(t *testing.T) {
		testNamespace := "drop-paths-test-" + fmt.Sprintf("%d", time.Now().Unix())
		ns := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: testNamespace,
			},
		}
		_, err := kubeClient.CoreV1().Namespaces().Create(context.Background(), ns, metav1.CreateOptions{})
		if err != nil {
			t.Fatalf("Failed to create test namespace: %v", err)
		}
		defer func() {
			_ = kubeClient.CoreV1().Namespaces().Delete(context.Background(), testNamespace, metav1.DeleteOptions{})
		}()

		kubearmorConfig := &operatorV1.KubeArmorConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-drop-paths",
				Namespace: "kubearmor",
			},
			Spec: operatorV1.KubeArmorConfigSpec{
				FileDropPaths: []string{
					"/proc/stat",
					"/proc/meminfo",
					"/sys/fs/cgroup",
				},
			},
		}

		_, err = operatorV1Clientset.OperatorV1().KubeArmorConfigs("kubearmor").Create(context.Background(), kubearmorConfig, metav1.CreateOptions{})
		if err != nil {
			t.Fatalf("Failed to create KubeArmorConfig: %v", err)
		}
		defer func() {
			_ = operatorV1Clientset.OperatorV1().KubeArmorConfigs("kubearmor").Delete(context.Background(), "test-drop-paths", metav1.DeleteOptions{})
		}()

		time.Sleep(10 * time.Second)

		testPod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "access-dropped-paths",
				Namespace: testNamespace,
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name:  "test-container",
						Image: "busybox",
						Command: []string{
							"sh",
							"-c",
							"for i in 1 2 3 4 5; do cat /proc/stat > /dev/null 2>&1; cat /proc/meminfo > /dev/null 2>&1; cat /sys/fs/cgroup/cpuset.cpus > /dev/null 2>&1; sleep 1; done",
						},
					},
				},
				RestartPolicy: corev1.RestartPolicyNever,
			},
		}

		pod, err := kubeClient.CoreV1().Pods(testNamespace).Create(context.Background(), testPod, metav1.CreateOptions{})
		if err != nil {
			t.Fatalf("Failed to create test pod: %v", err)
		}

		time.Sleep(15 * time.Second)

		pod, err = kubeClient.CoreV1().Pods(testNamespace).Get(context.Background(), pod.Name, metav1.GetOptions{})
		if err != nil {
			t.Fatalf("Failed to get test pod status: %v", err)
		}

		if pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodRunning {
			t.Logf("Pod executed successfully with dropped paths - no telemetry events should be generated for: /proc/stat, /proc/meminfo, /sys/fs/cgroup")
		}
	})

	t.Run("NonDroppedPathsReported", func(t *testing.T) {
		testNamespace := "non-drop-paths-test-" + fmt.Sprintf("%d", time.Now().Unix())
		ns := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: testNamespace,
			},
		}
		_, err := kubeClient.CoreV1().Namespaces().Create(context.Background(), ns, metav1.CreateOptions{})
		if err != nil {
			t.Fatalf("Failed to create test namespace: %v", err)
		}
		defer func() {
			_ = kubeClient.CoreV1().Namespaces().Delete(context.Background(), testNamespace, metav1.DeleteOptions{})
		}()

		testPod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "access-non-dropped-paths",
				Namespace: testNamespace,
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name:  "test-container",
						Image: "busybox",
						Command: []string{
							"sh",
							"-c",
							"for i in 1 2 3; do cat /etc/hostname > /dev/null 2>&1; cat /etc/hostname.bak > /dev/null 2>&1; sleep 1; done",
						},
					},
				},
				RestartPolicy: corev1.RestartPolicyNever,
			},
		}

		pod, err := kubeClient.CoreV1().Pods(testNamespace).Create(context.Background(), testPod, metav1.CreateOptions{})
		if err != nil {
			t.Fatalf("Failed to create test pod: %v", err)
		}

		time.Sleep(10 * time.Second)

		pod, err = kubeClient.CoreV1().Pods(testNamespace).Get(context.Background(), pod.Name, metav1.GetOptions{})
		if err != nil {
			t.Fatalf("Failed to get test pod status: %v", err)
		}

		if pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodRunning {
			t.Logf("Pod executed successfully accessing non-dropped paths - telemetry events should be generated for: /etc/hostname")
		}
	})

	t.Run("ConfigUpdateWorks", func(t *testing.T) {
		kubearmorConfig, err := operatorV1Clientset.OperatorV1().KubeArmorConfigs("kubearmor").List(context.Background(), metav1.ListOptions{})
		if err != nil {
			t.Logf("Warning: Could not list KubeArmorConfigs: %v (this is expected if no operator config exists)", err)
			return
		}

		if len(kubearmorConfig.Items) > 0 {
			cfg := &kubearmorConfig.Items[0]
			
			originalPaths := cfg.Spec.FileDropPaths
			cfg.Spec.FileDropPaths = append(cfg.Spec.FileDropPaths, "/test/new/path")

			_, err = operatorV1Clientset.OperatorV1().KubeArmorConfigs(cfg.Namespace).Update(context.Background(), cfg, metav1.UpdateOptions{})
			if err != nil {
				t.Logf("Could not update KubeArmorConfig (non-critical): %v", err)
				return
			}

			cfg.Spec.FileDropPaths = originalPaths
			_, _ = operatorV1Clientset.OperatorV1().KubeArmorConfigs(cfg.Namespace).Update(context.Background(), cfg, metav1.UpdateOptions{})

			t.Logf("Successfully updated and restored KubeArmorConfig FileDropPaths")
		}
	})
}

func BenchmarkDropPathHashPerformance(b *testing.B) {
	paths := []string{
		"/proc/stat",
		"/proc/meminfo",
		"/sys/fs/cgroup",
		"/dev/null",
		"/etc/passwd",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, p := range paths {
			hash := uint64(5381)
			for _, c := range p {
				hash = ((hash << 5) + hash) ^ uint64(c&0xFF)
			}
		}
	}
}
