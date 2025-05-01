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
	securityv1 "github.com/kubearmor/KubeArmor/pkg/KubeArmorController/api/security.kubearmor.com/v1"
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
	NRISocketLabel  string = "kubearmor.io/nri-socket"
	RandLabel       string = "kubearmor.io/rand"
	OsLabel         string = "kubernetes.io/os"
	ArchLabel       string = "kubernetes.io/arch"
	BTFLabel        string = "kubearmor.io/btf"
	ApparmorFsLabel string = "kubearmor.io/apparmorfs"
	SecurityFsLabel string = "kubearmor.io/securityfs"
	SeccompLabel    string = "kubearmor.io/seccomp"

	// node taints label
	NotreadyTaint      string = "node.kubernetes.io/not-ready"
	UnreachableTaint   string = "node.kubernetes.io/unreachable"
	UnschedulableTaint string = "node.kubernetes.io/unschedulable"

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
	ConfigGRPC                        string = "gRPC"
	ConfigVisibility                  string = "visibility"
	ConfigCluster                     string = "cluster"
	ConfigDefaultFilePosture          string = "defaultFilePosture"
	ConfigDefaultCapabilitiesPosture  string = "defaultCapabilitiesPosture"
	ConfigDefaultNetworkPosture       string = "defaultNetworkPosture"
	ConfigDefaultPostureLogs          string = "defaultPostureLogs"
	ConfigAlertThrottling             string = "alertThrottling"
	ConfigMaxAlertPerSec              string = "maxAlertPerSec"
	ConfigThrottleSec                 string = "throttleSec"
	ConfigEnableNRI                   string = "enableNRI"
	ConfigDropResourceFromProcessLogs string = "dropResourceFromProcessLogs"

	GlobalImagePullSecrets []corev1.LocalObjectReference = []corev1.LocalObjectReference{}
	GlobalTolerations      []corev1.Toleration           = []corev1.Toleration{}
	//KubearmorRelayEnvVariables

	EnableStdOutAlerts string = "enableStdOutAlerts"
	EnableStdOutLogs   string = "enableStdOutLogs"
	EnableStdOutMsgs   string = "enableStdOutMsgs"

	// Images
	KubeArmorName string   = "kubearmor"
	KubeArmorArgs []string = []string{
		"-gRPC=32767",
		"-procfsMount=/host/procfs",
		"-tlsEnabled=false",
	}
	KubeArmorImage            string                        = "kubearmor/kubearmor:stable"
	KubeArmorImagePullPolicy  string                        = "Always"
	KubeArmorImagePullSecrets []corev1.LocalObjectReference = []corev1.LocalObjectReference{}
	KubeArmorTolerations      []corev1.Toleration           = []corev1.Toleration{}

	KubeArmorInitName             string                        = "kubearmor-init"
	KubeArmorInitArgs             []string                      = []string{}
	KubeArmorInitImage            string                        = "kubearmor/kubearmor-init:stable"
	KubeArmorInitImagePullPolicy  string                        = "Always"
	KubeArmorInitImagePullSecrets []corev1.LocalObjectReference = []corev1.LocalObjectReference{}
	KubeArmorInitTolerations      []corev1.Toleration           = []corev1.Toleration{}

	KubeArmorRelayName string   = "kubearmor-relay"
	KubeArmorRelayArgs []string = []string{
		"-tlsEnabled=false",
	}
	KubeArmorRelayImage            string                        = "kubearmor/kubearmor-relay-server:latest"
	KubeArmorRelayImagePullPolicy  string                        = "Always"
	KubeArmorRelayImagePullSecrets []corev1.LocalObjectReference = []corev1.LocalObjectReference{}
	KubeArmorRelayTolerations      []corev1.Toleration           = []corev1.Toleration{}

	KubeArmorControllerName string   = "kubearmor-controller"
	KubeArmorControllerArgs []string = []string{
		"--leader-elect",
		"--health-probe-bind-address=:8081",
		"--annotateExisting=false",
	}
	KubeArmorControllerImage            string                        = "kubearmor/kubearmor-controller:latest"
	KubeArmorControllerImagePullPolicy  string                        = "Always"
	KubeArmorControllerImagePullSecrets []corev1.LocalObjectReference = []corev1.LocalObjectReference{}
	KubeArmorControllerTolerations      []corev1.Toleration           = []corev1.Toleration{}

	SeccompProfile     = "kubearmor-seccomp.json"
	SeccompInitProfile = "kubearmor-init-seccomp.json"

	// tls
	EnableTls                      bool     = false
	ExtraDnsNames                  []string = []string{"localhost"}
	ExtraIpAddresses               []string = []string{"127.0.0.1"}
	KubeArmorCaSecretName          string   = "kubearmor-ca"
	KubeArmorClientSecretName      string   = "kubearmor-client-certs"
	KubeArmorRelayServerSecretName string   = "kubearmor-relay-server-certs"
	DefaultTlsCertPath             string   = "/var/lib/kubearmor/tls"
	DefaultMode                    int32    = 420 // deciaml representation of octal value 644

	// throttling
	AlertThrottling       bool   = true
	DefaultMaxAlertPerSec string = "10"
	DefaultThrottleSec    string = "30"

	// recommend policies
	RecommendedPolicies opv1.RecommendedPolicies = opv1.RecommendedPolicies{
		MatchExpressions: []securityv1.MatchExpressionsType{
			{
				Key:      "namespace",
				Operator: "NotIn",
				Values: []string{
					"kube-system",
					"kubearmor",
				},
			},
		},
	}

	Adapter opv1.Adapters = opv1.Adapters{
		ElasticSearch: opv1.ElasticSearchAdapter{
			Enabled:         false,
			Url:             "",
			AlertsIndexName: "kubearmor-alerts",
			Auth: opv1.ElasticSearchAuth{
				SecretName:       "elastic-secret",
				UserNameKey:      "username",
				PasswordKey:      "password",
				AllowTlsInsecure: false,
				CAcertSecretName: "",
				CaCertKey:        "ca.crt",
			},
		},
	}

	ElasticSearchAdapterCaCertPath = "/cert"
)
var Pointer2True bool = true

var ConfigMapData = map[string]string{
	ConfigGRPC:                        "32767",
	ConfigCluster:                     "default",
	ConfigDefaultFilePosture:          "audit",
	ConfigDefaultCapabilitiesPosture:  "audit",
	ConfigDefaultNetworkPosture:       "audit",
	ConfigDropResourceFromProcessLogs: "false",
	ConfigVisibility:                  "process,network,capabilities",
	ConfigDefaultPostureLogs:          "true",
	ConfigAlertThrottling:             "true",
	ConfigMaxAlertPerSec:              "10",
	ConfigThrottleSec:                 "30",
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
	"nri": {
		"/var/run/nri/nri.sock",
		"/run/nri/nri.sock",
	},
}

var NRIEnabled = false

var HostPathDirectory = corev1.HostPathDirectory
var HostPathDirectoryOrCreate = corev1.HostPathDirectoryOrCreate
var HostPathSocket = corev1.HostPathSocket
var HostPathFile = corev1.HostPathFile

var EnforcerVolumesMounts = map[string][]corev1.VolumeMount{
	"apparmor": {
		{
			Name:      "etc-apparmor-d-path",
			MountPath: "/etc/apparmor.d",
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
}

var RuntimeSocketLocation = map[string]string{
	"docker":     "/var/run/docker.sock",
	"containerd": "/var/run/containerd/containerd.sock",
	"cri-o":      "/var/run/crio/crio.sock",
	"nri":        "/var/run/nri/nri.sock",
}

func ShortSHA(s string) string {
	sBytes := []byte(s)

	shaFunc := sha512.New()
	shaFunc.Write(sBytes)
	res := shaFunc.Sum(nil)
	return hex.EncodeToString(res)[:5]
}

var BPFVolumes = []corev1.Volume{
	{
		Name: "bpf",
		VolumeSource: corev1.VolumeSource{
			EmptyDir: &corev1.EmptyDirVolumeSource{},
		},
	},
}

var BPFVolumesMount = []corev1.VolumeMount{
	{
		Name:      "bpf",
		MountPath: "/opt/kubearmor/BPF",
	},
}

var CommonVolumes = []corev1.Volume{
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
		Name: "proc-fs-mount",
		VolumeSource: corev1.VolumeSource{
			HostPath: &corev1.HostPathVolumeSource{
				Path: "/proc",
				Type: &HostPathDirectory,
			},
		},
	},
}

var CommonVolumesMount = []corev1.VolumeMount{
	{
		Name:      "sys-kernel-debug-path",
		MountPath: "/sys/kernel/debug",
	},
	{
		Name:      "proc-fs-mount",
		MountPath: "/host/procfs",
		ReadOnly:  true,
	},
}

var KubeArmorCaVolume = []corev1.Volume{
	{
		Name: "kubearmor-ca-secret",
		VolumeSource: corev1.VolumeSource{
			Secret: &corev1.SecretVolumeSource{
				SecretName: KubeArmorCaSecretName,
				Items: []corev1.KeyToPath{
					{
						Key:  "tls.crt",
						Path: "ca.crt",
					},
					{
						Key:  "tls.key",
						Path: "ca.key",
					},
				},
				DefaultMode: &DefaultMode,
			},
		},
	},
}

var KubeArmorCaVolumeMount = []corev1.VolumeMount{
	{
		Name:      "kubearmor-ca-secret",
		MountPath: DefaultTlsCertPath,
		ReadOnly:  true,
	},
}

var KubeArmorRelayTlsVolume = []corev1.Volume{
	{
		Name: "kubearmor-relay-certs-secrets",
		VolumeSource: corev1.VolumeSource{
			Projected: &corev1.ProjectedVolumeSource{
				Sources: []corev1.VolumeProjection{
					{
						Secret: &corev1.SecretProjection{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: KubeArmorClientSecretName,
							},
							Items: []corev1.KeyToPath{
								{
									Key:  "tls.crt",
									Path: "client.crt",
								},
								{
									Key:  "tls.key",
									Path: "client.key",
								},
							},
						},
					},
					{
						Secret: &corev1.SecretProjection{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: KubeArmorRelayServerSecretName,
							},
							Items: []corev1.KeyToPath{
								{
									Key:  "tls.crt",
									Path: "server.crt",
								},
								{
									Key:  "tls.key",
									Path: "server.key",
								},
								{
									Key:  "ca.crt",
									Path: "ca.crt",
								},
							},
						},
					},
				},
				DefaultMode: &DefaultMode,
			},
		},
	},
}

var KubeArmorRelayTlsVolumeMount = []corev1.VolumeMount{
	{
		Name:      "kubearmor-relay-certs-secrets",
		MountPath: DefaultTlsCertPath,
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
	{
		Name:      "os-release-path",
		MountPath: "/media/root/etc/os-release",
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

func AddOrReplaceArg(add, replace string, args *[]string) {
	added := false
	for i, arg := range *args {
		if arg == replace || arg == add {
			(*args)[i] = add
			added = true
			break
		}
	}
	if !added {
		*args = append(*args, add)
	}
}

func GetTlsState() bool {
	return EnableTls
}

func AddOrRemoveVolumeMount(src *[]corev1.VolumeMount, dest *[]corev1.VolumeMount, action string) {
	for i, mnt := range *dest {
		for _, m := range *src {
			if mnt.Name == m.Name {
				(*dest)[i] = (*dest)[len(*dest)-1]
				*dest = (*dest)[:len(*dest)-1]
			}
		}
	}
	if action == AddAction {
		*dest = append(*dest, *src...)
	}
}

func AddOrRemoveVolume(src *[]corev1.Volume, dest *[]corev1.Volume, action string) {
	for i, mnt := range *dest {
		for _, m := range *src {
			if mnt.Name == m.Name {
				(*dest)[i] = (*dest)[len(*dest)-1]
				*dest = (*dest)[:len(*dest)-1]
			}
		}
	}
	if action == AddAction {
		*dest = append(*dest, *src...)
	}
}

func ParseArgument(arg string) (key string, value string, found bool) {
	arg = strings.TrimLeft(arg, "-")

	parts := strings.SplitN(arg, "=", 2)
	if len(parts) != 2 {
		return "", "", false
	}

	return parts[0], parts[1], true
}

func GenerateNRIvol(nriSocket string) (vol []corev1.Volume, volMnt []corev1.VolumeMount) {
	if nriSocket != "" {
		for _, socket := range ContainerRuntimeSocketMap["nri"] {
			if strings.ReplaceAll(socket[1:], "/", "_") == nriSocket {
				vol = append(vol, corev1.Volume{
					Name: "nri-socket",
					VolumeSource: corev1.VolumeSource{
						HostPath: &corev1.HostPathVolumeSource{
							Path: socket,
							Type: &HostPathSocket,
						},
					},
				})

				socket = RuntimeSocketLocation["nri"]
				volMnt = append(volMnt, corev1.VolumeMount{
					Name:      "nri-socket",
					MountPath: socket,
					ReadOnly:  true,
				})
				break
			}
		}
	}
	return
}
