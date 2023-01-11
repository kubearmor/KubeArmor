package common

import (
	"context"
	"crypto/sha512"
	"encoding/hex"
	"strings"

	deployments "github.com/kubearmor/KubeArmor/deployments/get"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/client-go/kubernetes"
)

var (
	EnforcerLabel                   string = "kubearmor.io/enforcer"
	RuntimeLabel                    string = "kubearmor.io/runtime"
	RuntimeStorageLabel             string = "kubearmor.io/runtime-storage"
	SocketLabel                     string = "kubearmor.io/socket"
	RandLabel                       string = "kubearmor.io/rand"
	OsLabel                         string = "kubernetes.io/os"
	ArchLabel                       string = "kubernetes.io/arch"
	DeletAction                     string = "DELETE"
	AddAction                       string = "ADD"
	Namespace                       string = "kube-system"
	Privileged                      bool   = true
	OperatorImage                   string = "kubearmor/kubearmor-operator:latest"
	KubeArmorServiceAccountName     string = "kubearmor"
	KubeArmorClusterRoleBindingName string = KubeArmorServiceAccountName
	KubeArmorSnitchRoleName         string = "kubearmor-snitch"
)

var ContainerRuntimeSocketMap = map[string][]string{
	"docker": {
		"/var/run/docker.sock",
		"/run/docker.sock",
	},
	"containerd": {
		"/var/snap/microk8s/common/run/containerd.sock",
		"/run/k3s/containerd/containerd.sock",
		"/run/containerd/containerd.sock",
		"/var/run/containerd/containerd.sock",
	},
	"crio": {
		"/run/crio/crio.sock",
	},
}

var HostPathDirectory = corev1.HostPathDirectory
var HostPathSocket = corev1.HostPathSocket

var EnforcerVolumesMounts = map[string][]corev1.VolumeMount{
	"apparmor": {
		{
			Name:      "etc-apparmor-d-path",
			MountPath: "/etc/apparmor.d",
		},
	},
	"bpf": {
		{
			Name:      "sys-fs-bpf-path",
			MountPath: "/sys/fs/bpf",
		},
	},
}

var EnforcerVolumes = map[string][]corev1.Volume{
	"apparmor": {
		{
			Name: "etc-apparmor-d-path",
			VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{
					Path: "/etc/apparmor.d",
					Type: &HostPathDirectory,
				},
			},
		},
	},
	"bpf": {

		{
			Name: "sys-fs-bpf-path",
			VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{
					Path: "/sys/fs/bpf",
					Type: &HostPathDirectory,
				},
			},
		},
	},
}

var RuntimeStorageVolumes = map[string][]string{
	"docker": {
		"/var/lib/docker",
	},
	"crio": {
		"/var/lib/containers/storage",
	},
	"containerd": {
		"/run/k3s/containerd",
		"/run/containerd",
	},
}

func ShortSHA(s string) string {
	sBytes := []byte(s)

	shaFunc := sha512.New()
	shaFunc.Write(sBytes)
	res := shaFunc.Sum(nil)
	return hex.EncodeToString(res)[:5]
}

var CommonVolumes = []corev1.Volume{
	{
		Name: "bpf",
		VolumeSource: corev1.VolumeSource{
			EmptyDir: &corev1.EmptyDirVolumeSource{},
		},
	},
	{
		Name: "sys-kernel-security-path",
		VolumeSource: corev1.VolumeSource{
			HostPath: &corev1.HostPathVolumeSource{
				Path: "/sys/kernel/security",
				Type: &HostPathDirectory,
			},
		},
	},
	{
		Name: "sys-kernel-debug-path",
		VolumeSource: corev1.VolumeSource{
			HostPath: &corev1.HostPathVolumeSource{
				Path: "/sys/kernel/debug",
				Type: &HostPathDirectory,
			},
		},
	},
}

var CommonVolumesMount = []corev1.VolumeMount{
	{
		Name:      "bpf",
		MountPath: "/opt/kubearmor/BPF",
	},
	{
		Name:      "sys-kernel-security-path",
		MountPath: "/sys/kernel/security",
	},
	{
		Name:      "sys-kernel-debug-path",
		MountPath: "/sys/kernel/debug",
	},
}

func GetFreeRandSuffix(c *kubernetes.Clientset, namespace string) (suffix string, err error) {
	var found bool
	for {
		suffix = rand.String(5)
		found = false
		if _, err = c.AdmissionregistrationV1().MutatingWebhookConfigurations().Get(context.Background(), deployments.AnnotationsControllerServiceName+"-"+suffix, metav1.GetOptions{}); err != nil {
			if !strings.Contains(err.Error(), "not found") {
				return "", err
			}
		} else {
			found = true
		}

		if _, err = c.CoreV1().Services(namespace).Get(context.Background(), deployments.AnnotationsControllerServiceName+"-"+suffix, metav1.GetOptions{}); err != nil {
			if !strings.Contains(err.Error(), "not found") {
				return "", err
			}
		} else {
			found = true
		}

		if _, err = c.AppsV1().Deployments(namespace).Get(context.Background(), deployments.AnnotationsControllerDeploymentName+"-"+suffix, metav1.GetOptions{}); err != nil {
			if !strings.Contains(err.Error(), "not found") {
				return "", err
			}
		} else {
			found = true
		}

		if _, err = c.CoreV1().Secrets(namespace).Get(context.Background(), deployments.KubeArmorControllerSecretName+"-"+suffix, metav1.GetOptions{}); err != nil {
			if !strings.Contains(err.Error(), "not found") {
				return "", err
			}
		} else {
			found = true
		}

		if !found {
			break
		}
	}
	return suffix, nil
}
