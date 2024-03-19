// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package common

import (
	"context"
	"crypto/sha512"
	"encoding/hex"
	"os"
	"strings"

	deployments "github.com/kubearmor/KubeArmor/deployments/get"
	opv1 "github.com/kubearmor/KubeArmor/pkg/KubeArmorOperator/api/operator.kubearmor.com/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/client-go/kubernetes"
)

const (
	// constants for CRD status
	CREATED  string = "Created"
	PENDING  string = "Pending"
	RUNNING  string = "Running"
	UPDATING string = "Updating"
	ERROR    string = "Error"

	// Status Messages
	CREATED_MSG  string = "Installation has been created"
	PENDING_MSG  string = "Kubearmor Installation is in-progress"
	RUNNING_MSG  string = "Kubearmor Application is Up and Running"
	UPDATING_MSG string = "Updating the Application Configuration"

	// Error Messages
	INSTALLATION_ERR_MSG    string = "Failed to install KubeArmor component(s)"
	MULTIPLE_CRD_ERR_MSG    string = "There's already a CRD exists to manage KubeArmor"
	UPDATION_FAILED_ERR_MSG string = "Failed to update KubeArmor configuration"
)

var OperatorConfigCrd *opv1.KubeArmorConfig

var (
	// node labels
	EnforcerLabel   string = "kubearmor.io/enforcer"
	RuntimeLabel    string = "kubearmor.io/runtime"
	SocketLabel     string = "kubearmor.io/socket"
	RandLabel       string = "kubearmor.io/rand"
	OsLabel         string = "kubernetes.io/os"
	ArchLabel       string = "kubernetes.io/arch"
	BTFLabel        string = "kubearmor.io/btf"
	ApparmorFsLabel string = "kubearmor.io/apparmorfs"
	SecurityFsLabel string = "kubearmor.io/securityfs"
	SeccompLabel    string = "kubearmor.io/seccomp"

	// if any node with securityfs/lsm present
	IfNodeWithSecurtiyFs bool = false

	DeleteAction            string = "DELETE"
	AddAction               string = "ADD"
	Namespace               string = "kubearmor"
	Privileged              bool   = false
	HostPID                 bool   = false
	SnitchName              string = "kubearmor-snitch"
	SnitchImage             string = "kubearmor/kubearmor-snitch"
	SnitchImageTag          string = "latest"
	KubeArmorSnitchRoleName string = "kubearmor-snitch"

	// KubeArmorConfigMapName string = "kubearmor-config"

	// ConfigMap Data
	ConfigGRPC                       string = "gRPC"
	ConfigVisibility                 string = "visibility"
	ConfigCluster                    string = "cluster"
	ConfigDefaultFilePosture         string = "defaultFilePosture"
	ConfigDefaultCapabilitiesPosture string = "defaultCapabilitiesPosture"
	ConfigDefaultNetworkPosture      string = "defaultNetworkPosture"
	ConfigDefaultPostureLogs         string = "defaultPostureLogs"

	//KubearmorRelayEnvVariables

	EnableStdOutAlerts string = "enableStdOutAlerts"
	EnableStdOutLogs   string = "enableStdOutLogs"
	EnableStdOutMsgs   string = "enableStdOutMsgs"

	// Images
	KubeArmorName                      string = "kubearmor"
	KubeArmorImage                     string = "kubearmor/kubearmor:stable"
	KubeArmorImagePullPolicy           string = "Always"
	KubeArmorInitName                  string = "kubearmor-init"
	KubeArmorInitImage                 string = "kubearmor/kubearmor-init:stable"
	KubeArmorInitImagePullPolicy       string = "Always"
	KubeArmorRelayName                 string = "kubearmor-relay"
	KubeArmorRelayImage                string = "kubearmor/kubearmor-relay-server:latest"
	KubeArmorRelayImagePullPolicy      string = "Always"
	KubeArmorControllerName            string = "kubearmor-controller"
	KubeArmorControllerImage           string = "kubearmor/kubearmor-controller:latest"
	KubeArmorControllerImagePullPolicy string = "Always"
	KubeRbacProxyName                  string = "kube-rbac-proxy"
	KubeRbacProxyImage                 string = "gcr.io/kubebuilder/kube-rbac-proxy:v0.15.0"
	KubeRbacProxyImagePullPolicy       string = "Always"
	SeccompProfile                            = "kubearmor-seccomp.json"
	SeccompInitProfile                        = "kubearmor-init-seccomp.json"
)

var ConfigMapData = map[string]string{
	ConfigGRPC:                       "32767",
	ConfigCluster:                    "default",
	ConfigDefaultFilePosture:         "audit",
	ConfigDefaultCapabilitiesPosture: "audit",
	ConfigDefaultNetworkPosture:      "audit",
	ConfigVisibility:                 "process,network,capabilities",
	ConfigDefaultPostureLogs:         "true",
}

var ConfigDefaultSeccompEnabled = "false"

var KubearmorRelayEnvMap = map[string]string{
	EnableStdOutAlerts: "false",
	EnableStdOutLogs:   "false",
	EnableStdOutMsgs:   "false",
}

var ContainerRuntimeSocketMap = map[string][]string{
	"docker": {
		"/run/containerd/containerd.sock",
		"/var/run/containerd/containerd.sock",
		"/var/run/docker.sock",
		"/run/docker.sock",
	},
	"containerd": {
		"/var/snap/microk8s/common/run/containerd.sock",
		"/run/k0s/containerd.sock",
		"/run/k3s/containerd/containerd.sock",
		"/run/containerd/containerd.sock",
		"/var/run/containerd/containerd.sock",
		"/run/dockershim.sock",
	},
	"cri-o": {
		"/var/run/crio/crio.sock",
		"/run/crio/crio.sock",
	},
}

var HostPathDirectory = corev1.HostPathDirectory
var HostPathSocket = corev1.HostPathSocket
var HostPathFile = corev1.HostPathFile

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

var RuntimeSocketLocation = map[string]string{
	"docker":     "/var/run/docker.sock",
	"containerd": "/var/run/containerd/containerd.sock",
	"cri-o":      "/var/run/crio/crio.sock",
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
		Name: "sys-kernel-debug-path",
		VolumeSource: corev1.VolumeSource{
			HostPath: &corev1.HostPathVolumeSource{
				Path: "/sys/kernel/debug",
				Type: &HostPathDirectory,
			},
		},
	},
	{
		Name: "os-release-path",
		VolumeSource: corev1.VolumeSource{
			HostPath: &corev1.HostPathVolumeSource{
				Path: "/etc/os-release",
				Type: &HostPathFile,
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
		Name:      "sys-kernel-debug-path",
		MountPath: "/sys/kernel/debug",
	},
	{
		Name:      "os-release-path",
		MountPath: "/media/root/etc/os-release",
		ReadOnly:  true,
	},
}

var KernelHeaderVolumes = []corev1.Volume{
	{
		Name: "lib-modules-path",
		VolumeSource: corev1.VolumeSource{
			HostPath: &corev1.HostPathVolumeSource{
				Path: "/lib/modules",
				Type: &HostPathDirectory,
			},
		},
	},
	{
		Name: "usr-src-path",
		VolumeSource: corev1.VolumeSource{
			HostPath: &corev1.HostPathVolumeSource{
				Path: "/usr/src",
				Type: &HostPathDirectory,
			},
		},
	},
}

var KernelHeaderVolumesMount = []corev1.VolumeMount{
	{
		Name:      "usr-src-path",
		MountPath: "/usr/src",
		ReadOnly:  true,
	},
	{
		Name:      "lib-modules-path",
		MountPath: "/lib/modules",
		ReadOnly:  true,
	},
}

func GetFreeRandSuffix(c *kubernetes.Clientset, namespace string) (suffix string, err error) {
	var found bool
	for {
		suffix = rand.String(5)
		found = false
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

func GetOperatorNamespace() string {
	ns := os.Getenv("KUBEARMOR_OPERATOR_NS")

	if ns == "" {
		return Namespace
	}

	return ns
}

func GetApplicationImage(app string) string {
	// RELATED_IMAGE_* env variables will be present in case of redhat certified operator
	switch app {
	case KubeArmorName:
		if image := os.Getenv("RELATED_IMAGE_KUBEARMOR"); image != "" {
			return image
		}
		return KubeArmorImage
	case KubeArmorInitName:
		if image := os.Getenv("RELATED_IMAGE_KUBEARMOR_INIT"); image != "" {
			return image
		}
		return KubeArmorInitImage
	case KubeArmorRelayName:
		if image := os.Getenv("RELATED_IMAGE_KUBEARMOR_RELAY_SERVER"); image != "" {
			return image
		}
		return KubeArmorRelayImage
	case KubeArmorControllerName:
		if image := os.Getenv("RELATED_IMAGE_KUBEARMOR_CONTROLLER"); image != "" {
			return image
		}
		return KubeArmorControllerImage
	case KubeRbacProxyName:
		if image := os.Getenv("RELATED_IMAGE_KUBE_RBAC_PROXY"); image != "" {
			return image
		}
		return KubeRbacProxyImage
	case SnitchName:
		if image := os.Getenv("RELATED_IMAGE_KUBEARMOR_SNITCH"); image != "" {
			return image
		}
		return SnitchImage + ":" + SnitchImageTag
	}
	return ""
}

func IsCertifiedOperator() bool {
	certified := os.Getenv("REDHAT_CERTIFIED_OP")
	if certified == "" {
		return false
	}
	return true
}

func CopyStrMap(src map[string]string) map[string]string {
	newMap := make(map[string]string)
	for key, value := range src {
		newMap[key] = value
	}
	return newMap
}

func init() {
	Namespace = GetOperatorNamespace()
	if IsCertifiedOperator() {
		HostPID = true
	}
}
