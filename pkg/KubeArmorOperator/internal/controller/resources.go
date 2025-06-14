// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package controller

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	deployments "github.com/kubearmor/KubeArmor/deployments/get"
	crds "github.com/kubearmor/KubeArmor/pkg/KubeArmorController/crd"
	certGen "github.com/kubearmor/KubeArmor/pkg/KubeArmorOperator/cert"
	"github.com/kubearmor/KubeArmor/pkg/KubeArmorOperator/common"
	v1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	extv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1errors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func generateDaemonset(name, enforcer, runtime, socket, nriSocket, btfPresent, apparmorfs, seccompPresent string, initDeploy bool) *appsv1.DaemonSet {
	enforcerVolumes := []corev1.Volume{}
	enforcerVolumeMounts := []corev1.VolumeMount{}
	if !(enforcer == "apparmor" && apparmorfs == "no") {
		enforcerVolumes, enforcerVolumeMounts = genEnforcerVolumes(enforcer)
	}
	runtimeVolumes, runtimeVolumeMounts := genRuntimeVolumes(runtime, socket, nriSocket)
	vols := []corev1.Volume{}
	volMnts := []corev1.VolumeMount{}
	vols = append(vols, enforcerVolumes...)
	vols = append(vols, runtimeVolumes...)
	volMnts = append(volMnts, enforcerVolumeMounts...)
	volMnts = append(volMnts, runtimeVolumeMounts...)
	commonVols := common.CommonVolumes
	commonVolMnts := common.CommonVolumesMount

	if initDeploy || btfPresent == "no" {
		if btfPresent == "no" {
			commonVols = append(commonVols, common.KernelHeaderVolumes...)
			commonVolMnts = append(commonVolMnts, common.KernelHeaderVolumesMount...)
		}
		commonVols = append(commonVols, common.BPFVolumes...)
		commonVolMnts = append(commonVolMnts, common.BPFVolumesMount...)
	}
	vols = append(vols, commonVols...)
	volMnts = append(volMnts, commonVolMnts...)
	daemonset := deployments.GenerateDaemonSet("generic", common.Namespace)

	if btfPresent != "no" && !initDeploy {
		daemonset.Spec.Template.Spec.InitContainers = []corev1.Container{}
	}

	if nriSocket != "" && common.NRIEnabled {
		name = strings.Join([]string{
			"kubearmor",
			strings.ReplaceAll(enforcer, ".", "-"),
			"nri",
			common.ShortSHA(nriSocket),
		}, "-")
	}

	daemonset.Name = name
	labels := map[string]string{
		common.EnforcerLabel: enforcer,
		common.RuntimeLabel:  runtime,
		common.SocketLabel:   socket,
		common.OsLabel:       "linux",
		common.BTFLabel:      btfPresent,
		common.SeccompLabel:  seccompPresent,
	}
	if nriSocket != "" {
		labels[common.NRISocketLabel] = nriSocket
	}
	daemonset.Spec.Template.Spec.NodeSelector = common.CopyStrMap(labels)
	labels["kubearmor-app"] = "kubearmor"
	daemonset.Spec.Template.Labels = labels
	daemonset.Spec.Template.Spec.ServiceAccountName = "kubearmor"
	daemonset.Spec.Selector = &metav1.LabelSelector{
		MatchLabels: labels,
	}
	if deployment_uuid != "" {
		daemonset.OwnerReferences = []metav1.OwnerReference{
			{
				APIVersion: "apps/v1",
				Kind:       "Deployment",
				Name:       deployment_name,
				UID:        deployment_uuid,
			},
		}
	}

	// TODO: handle passing annotateResource flag to kubearmor
	// ideally this configuration should be part of kubearmoconfig to avoid hardcoding version checks
	// to detect flag compatibility

	// if annotateResource {
	// 	common.AddOrReplaceArg("-annotateResource=true", "-annotateResource=false", &daemonset.Spec.Template.Spec.Containers[0].Args)
	// } else {
	// 	common.AddOrReplaceArg("-annotateResource=false", "-annotateResource=true", &daemonset.Spec.Template.Spec.Containers[0].Args)
	// }

	if common.EnableTls {
		vols = append(vols, common.KubeArmorCaVolume...)
		volMnts = append(volMnts, common.KubeArmorCaVolumeMount...)
		common.AddOrReplaceArg("-tlsEnabled=true", "-tlsEnabled=false", &daemonset.Spec.Template.Spec.Containers[0].Args)
	} else {
		common.AddOrReplaceArg("-tlsEnabled=false", "-tlsEnabled=true", &daemonset.Spec.Template.Spec.Containers[0].Args)
	}
	daemonset.Spec.Template.Spec.Volumes = vols
	daemonset.Spec.Template.Spec.Containers[0].VolumeMounts = volMnts

	if btfPresent == "no" || initDeploy {
		daemonset.Spec.Template.Spec.InitContainers[0].VolumeMounts = commonVolMnts
		daemonset.Spec.Template.Spec.InitContainers[0].Image = common.GetApplicationImage(common.KubeArmorInitName)
		daemonset.Spec.Template.Spec.InitContainers[0].ImagePullPolicy = corev1.PullPolicy(common.KubeArmorInitImagePullPolicy)
		UpdateArgsIfDefinedAndUpdated(&daemonset.Spec.Template.Spec.InitContainers[0].Args, common.KubeArmorInitArgs)
		UpdateImagePullSecretsIfDefinedAndUpdated(&daemonset.Spec.Template.Spec.ImagePullSecrets, common.KubeArmorInitImagePullSecrets)
		UpdateTolerationsIfDefinedAndUpdated(&daemonset.Spec.Template.Spec.Tolerations, common.KubeArmorInitTolerations)
	}
	// update images
	if seccompPresent == "yes" && common.ConfigDefaultSeccompEnabled == "true" {
		daemonset.Spec.Template.Spec.Containers[0].SecurityContext.SeccompProfile = &corev1.SeccompProfile{
			Type:             corev1.SeccompProfileTypeLocalhost,
			LocalhostProfile: &common.SeccompProfile,
		}
		if len(daemonset.Spec.Template.Spec.InitContainers) != 0 {
			daemonset.Spec.Template.Spec.InitContainers[0].SecurityContext.SeccompProfile = &corev1.SeccompProfile{
				Type:             corev1.SeccompProfileTypeLocalhost,
				LocalhostProfile: &common.SeccompInitProfile,
			}
		}

	}

	daemonset.Spec.Template.Spec.Containers[0].Image = common.GetApplicationImage(common.KubeArmorName)
	daemonset.Spec.Template.Spec.Containers[0].ImagePullPolicy = corev1.PullPolicy(common.KubeArmorImagePullPolicy)
	UpdateArgsIfDefinedAndUpdated(&daemonset.Spec.Template.Spec.Containers[0].Args, common.KubeArmorArgs)
	UpdateImagePullSecretsIfDefinedAndUpdated(&daemonset.Spec.Template.Spec.ImagePullSecrets, common.KubeArmorImagePullSecrets)
	UpdateTolerationsIfDefinedAndUpdated(&daemonset.Spec.Template.Spec.Tolerations, common.KubeArmorInitTolerations)
	if len(daemonset.Spec.Template.Spec.ImagePullSecrets) < 1 {
		updateImagePullSecretFromGlobal(common.GlobalImagePullSecrets, &daemonset.Spec.Template.Spec.ImagePullSecrets)
	}
	if len(daemonset.Spec.Template.Spec.Tolerations) < 1 {
		updateTolerationFromGlobal(common.GlobalTolerations, &daemonset.Spec.Template.Spec.Tolerations)
	}
	daemonset = addOwnership(daemonset).(*appsv1.DaemonSet)
	fmt.Printf("generated daemonset: %v", daemonset)
	return daemonset
}

func genEnforcerVolumes(enforcer string) (vol []corev1.Volume, volMnt []corev1.VolumeMount) {
	if enforcer == "none" {
		return nil, nil
	}
	for _, e := range strings.Split(enforcer, ".") {
		vol = append(vol, common.EnforcerVolumes[e]...)
		volMnt = append(volMnt, common.EnforcerVolumesMounts[e]...)
	}
	return
}

func genRuntimeVolumes(runtime, runtimeSocket, nriSocket string) (vol []corev1.Volume, volMnt []corev1.VolumeMount) {
	// lookup socket
	for _, socket := range common.ContainerRuntimeSocketMap[runtime] {
		if strings.ReplaceAll(socket[1:], "/", "_") == runtimeSocket {
			vol = append(vol, corev1.Volume{
				Name: runtime + "-socket",
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{
						Path: socket,
						Type: &common.HostPathSocket,
					},
				},
			})

			socket = common.RuntimeSocketLocation[runtime]
			volMnt = append(volMnt, corev1.VolumeMount{
				Name:      runtime + "-socket",
				MountPath: socket,
				ReadOnly:  true,
			})
			break
		}
	}
	if nriSocket != "" && common.NRIEnabled {
		runtime = "nri"
		for _, socket := range common.ContainerRuntimeSocketMap[runtime] {
			if strings.ReplaceAll(socket[1:], "/", "_") == nriSocket {
				vol = append(vol, corev1.Volume{
					Name: runtime + "-socket",
					VolumeSource: corev1.VolumeSource{
						HostPath: &corev1.HostPathVolumeSource{
							Path: socket,
							Type: &common.HostPathSocket,
						},
					},
				})

				socket = common.RuntimeSocketLocation[runtime]
				volMnt = append(volMnt, corev1.VolumeMount{
					Name:      runtime + "-socket",
					MountPath: socket,
					ReadOnly:  true,
				})
				break
			}
		}
	}
	return
}

func genSnitchRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name:      common.KubeArmorSnitchRoleName,
			Namespace: common.Namespace,
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Verbs: []string{
					"get",
					"patch",
				},
				Resources: []string{
					"nodes",
				},
			},
		},
	}
}

func genSnitchRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: common.KubeArmorSnitchRoleName + "-binding",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      common.KubeArmorSnitchRoleName,
				Namespace: common.Namespace,
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     common.KubeArmorSnitchRoleName,
		},
	}
}

func genSnitchServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      common.KubeArmorSnitchRoleName,
			Namespace: common.Namespace,
		},
	}
}

func deploySnitch(nodename string, runtime string) *batchv1.Job {
	job := batchv1.Job{}
	job = *addOwnership(&job).(*batchv1.Job)
	ttls := int32(100)
	job.GenerateName = "kubearmor-snitch-"
	var rootUser int64 = 0
	job.Spec = batchv1.JobSpec{
		TTLSecondsAfterFinished: &ttls,
		Template: corev1.PodTemplateSpec{
			ObjectMeta: metav1.ObjectMeta{
				Labels: map[string]string{
					"kubearmor-app": common.KubeArmorSnitchRoleName,
				},
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name:  "snitch",
						Image: common.GetApplicationImage(common.SnitchName),
						Args: []string{
							"--nodename=$(NODE_NAME)",
							"--pathprefix=" + PathPrefix,
							"--runtime=" + runtime,
						},
						Env: []corev1.EnvVar{
							{
								Name: "NODE_NAME",
								ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{
									FieldPath: "spec.nodeName",
								}},
							},
						},
						ImagePullPolicy: corev1.PullIfNotPresent,
						VolumeMounts: []corev1.VolumeMount{

							{
								Name:      "var-path",
								MountPath: "/rootfs/var/",
								ReadOnly:  true,
							},
							{
								Name:      "run-path",
								MountPath: "/rootfs/run/",
								ReadOnly:  true,
							},
							{
								Name:      "sys-path",
								MountPath: "/rootfs/sys/",
								ReadOnly:  true,
							},
							{
								Name:      "apparmor-path",
								MountPath: "/rootfs/etc/apparmor.d/",
								ReadOnly:  true,
							},
							{
								Name:      "seccomp-path",
								MountPath: "/var/lib/kubelet/seccomp",
							},
						},
						SecurityContext: &corev1.SecurityContext{
							RunAsUser:  &rootUser,
							RunAsGroup: &rootUser,
							Capabilities: &corev1.Capabilities{
								Add: []corev1.Capability{
									"IPC_LOCK",
									"SYS_ADMIN",
									"SYS_RESOURCE",
								},
								Drop: []corev1.Capability{
									"ALL",
								},
							},
							Privileged: &(common.Privileged),
						},
					},
				},
				// For Unknown Reasons hostPID will be true if snitch gets deployed on OpenShift
				// for some reasons github.com/kubearmor/KubeArmor/KubeArmor/utils/bpflsmprobe will
				// not work if hostPID is set false.

				// change for snitch host path
				HostPID:            common.HostPID,
				NodeName:           nodename,
				RestartPolicy:      corev1.RestartPolicyOnFailure,
				ServiceAccountName: common.KubeArmorSnitchRoleName,
				Volumes: []corev1.Volume{
					{
						Name: "sys-path",
						VolumeSource: corev1.VolumeSource{
							HostPath: &corev1.HostPathVolumeSource{
								Path: "/sys/",
								Type: &common.HostPathDirectory,
							},
						},
					},
					{
						Name: "apparmor-path",
						VolumeSource: corev1.VolumeSource{
							HostPath: &corev1.HostPathVolumeSource{
								Path: "/etc/apparmor.d/",
								Type: &common.HostPathDirectory,
							},
						},
					},
					{
						Name: "var-path",
						VolumeSource: corev1.VolumeSource{
							HostPath: &corev1.HostPathVolumeSource{
								Path: "/var/",
								Type: &common.HostPathDirectory,
							},
						},
					},
					{
						Name: "run-path",
						VolumeSource: corev1.VolumeSource{
							HostPath: &corev1.HostPathVolumeSource{
								Path: "/run/",
								Type: &common.HostPathDirectory,
							},
						},
					},
					{
						Name: "seccomp-path",
						VolumeSource: corev1.VolumeSource{
							HostPath: &corev1.HostPathVolumeSource{
								Path: "/var/lib/kubelet/seccomp",
								Type: &common.HostPathDirectoryOrCreate,
							},
						},
					},
				},
			},
		},
	}
	return &job
}

func isNotfound(err error) bool {
	return err != nil && strings.Contains(err.Error(), "not found")
}

func isAlreadyExists(err error) bool {
	return err != nil && strings.Contains(err.Error(), "already exist")
}

func addOwnership(obj interface{}) interface{} {
	if deployment_uuid == "" {
		return obj
	}
	OwnerReferences := []metav1.OwnerReference{
		{
			APIVersion: "apps/v1",
			Kind:       "Deployment",
			Name:       deployment_name,
			UID:        deployment_uuid,
		},
	}
	switch resource := obj.(type) {
	case *corev1.ServiceAccount:
		resource.OwnerReferences = OwnerReferences
		return resource
	case *corev1.Service:
		resource.OwnerReferences = OwnerReferences
		return resource
	case *appsv1.Deployment:
		resource.OwnerReferences = OwnerReferences
		return resource
	case *corev1.Secret:
		resource.OwnerReferences = OwnerReferences
		return resource
	case *appsv1.DaemonSet:
		resource.OwnerReferences = OwnerReferences
		return resource
	case *batchv1.Job:
		resource.OwnerReferences = OwnerReferences
		return resource
	case *extv1.CustomResourceDefinition:
		resource.OwnerReferences = OwnerReferences
		return resource
	case *corev1.ConfigMap:
		resource.OwnerReferences = OwnerReferences
		return resource
	}
	return obj
}

func (clusterWatcher *ClusterWatcher) AreAllNodesProcessed() bool {
	processedNodes := 0
	clusterWatcher.DaemonsetsLock.Lock()
	clusterWatcher.NodesLock.Lock()

	processedNodes = len(clusterWatcher.Nodes)
	dsCount := 0
	for _, ds := range clusterWatcher.Daemonsets {
		if ds > 0 {
			dsCount += ds
		}
	}

	clusterWatcher.NodesLock.Unlock()
	clusterWatcher.DaemonsetsLock.Unlock()

	nodes, err := clusterWatcher.Client.CoreV1().Nodes().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		clusterWatcher.Log.Warnf("Cannot list nodes, error=%s", err.Error())
		return false
	}
	if !(len(nodes.Items) == processedNodes) {
		return false
	}

	// check if there's any node with securityfs/lsm exists
	common.IfNodeWithSecurtiyFs = false
	for _, node := range nodes.Items {
		if val, ok := node.Labels[common.SecurityFsLabel]; ok {
			switch val {
			case "yes":
				common.IfNodeWithSecurtiyFs = true
			}
		}
	}

	kaPodsList, err := clusterWatcher.Client.CoreV1().Pods(common.Namespace).List(context.Background(), metav1.ListOptions{
		LabelSelector: "kubearmor-app=kubearmor",
	})
	return len(kaPodsList.Items) == dsCount

}

func (clusterWatcher *ClusterWatcher) deployControllerDeployment(deployment *appsv1.Deployment) error {
	deployment = addOwnership(deployment).(*appsv1.Deployment)

	// add port to controller deployment
	common.ControllerPortLock.Lock()
	deployment.Spec.Template.Spec.Containers[0].Ports[0].ContainerPort = int32(common.KubeArmorControllerPort)
	UpdateArgsIfDefinedAndUpdated(&deployment.Spec.Template.Spec.Containers[0].Args, []string{"webhook-port=" + strconv.Itoa(common.KubeArmorControllerPort)})
	common.ControllerPortLock.Unlock()
	if common.IfNodeWithSecurtiyFs {
		deployment.Spec.Template.Spec.NodeSelector = map[string]string{
			common.SecurityFsLabel: "yes",
		}
	} else {
		deployment.Spec.Template.Spec.NodeSelector = nil
	}
	controller, err := clusterWatcher.Client.AppsV1().Deployments(common.Namespace).Get(context.Background(), deployment.Name, metav1.GetOptions{})
	if isNotfound(err) {
		clusterWatcher.Log.Infof("Creating deployment %s", deployment.Name)
		_, err = clusterWatcher.Client.AppsV1().Deployments(common.Namespace).Create(context.Background(), deployment, metav1.CreateOptions{})
		if err != nil {
			clusterWatcher.Log.Warnf("Cannot create deployment %s, error=%s", deployment.Name, err.Error())
			return err
		}
	} else {
		if (common.IfNodeWithSecurtiyFs && controller.Spec.Template.Spec.NodeSelector == nil) ||
			(!common.IfNodeWithSecurtiyFs && controller.Spec.Template.Spec.NodeSelector != nil) || !reflect.DeepEqual(controller.Spec.Template.Spec.Containers[0].Args, deployment.Spec.Template.Spec.Containers[0].Args) {
			clusterWatcher.Log.Infof("Updating deployment %s", controller.Name)
			controller.Spec.Template.Spec.NodeSelector = deployment.Spec.Template.Spec.NodeSelector
			controller.Spec.Template.Spec.Containers = deployment.Spec.Template.Spec.Containers
			clusterWatcher.Log.Infoln("updated deployment", controller)
			_, err = clusterWatcher.Client.AppsV1().Deployments(common.Namespace).Update(context.Background(), controller, metav1.UpdateOptions{})
			if err != nil {
				clusterWatcher.Log.Warnf("Cannot update deployment %s, error=%s", deployment.Name, err.Error())
				return err
			}
		}
	}
	return nil
}

func (clusterWatcher *ClusterWatcher) getProvider(providerHostname, providerEndpoint string) (string, string, string) {
	nodes, err := clusterWatcher.Client.CoreV1().Nodes().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		clusterWatcher.Log.Warnf("Error listing nodes: %s\n", err.Error())
	}

	for _, node := range nodes.Items {
		for key, label := range node.Labels {
			if strings.Contains(key, "gke") || strings.Contains(label, "gke") {
				if providerHostname != "" && providerEndpoint == "" {
					providerEndpoint = "/computeMetadata/v1/instance/attributes/cluster-name"
				} else if providerHostname == "" && providerEndpoint != "" {
					providerHostname = "http://metadata.google.internal"
				} else if providerHostname == "" && providerEndpoint == "" {
					providerHostname = "http://metadata.google.internal"
					providerEndpoint = "/computeMetadata/v1/instance/attributes/cluster-name"
				}
				return "gke", providerHostname, providerEndpoint
			} else if strings.Contains(key, "eks") || strings.Contains(label, "eks") {
				if providerHostname != "" && providerEndpoint == "" {
					providerEndpoint = "/latest/user-data"
				} else if providerHostname == "" && providerEndpoint != "" {
					providerHostname = "http://169.254.169.254"
				} else if providerHostname == "" && providerEndpoint == "" {
					providerHostname = "http://169.254.169.254"
					providerEndpoint = "/latest/user-data"
				}
				return "eks", providerHostname, providerEndpoint
			}
		}
	}
	return "default", "", ""
}

func (clusterWatcher *ClusterWatcher) fetchClusterNameFromGKE(providerHostname, providerEndpoint string) (string, error) {
	url := providerHostname + providerEndpoint
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		clusterWatcher.Log.Warnf("failed to create request: %w, check provider host name and endpoint", err)
		return "", err
	}

	// Set the required header
	req.Header.Set("Metadata-Flavor", "Google")

	// Create an HTTP client and make the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		clusterWatcher.Log.Warnf("error making request: %w, check provider host name and endpoint", err)
		return "", err
	}
	defer resp.Body.Close()

	// Check for a successful response
	if resp.StatusCode != http.StatusOK {
		clusterWatcher.Log.Warnf("failed to fetch from metadata, status code: %d", resp.StatusCode)
		return "", err
	}

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		clusterWatcher.Log.Warnf("error reading response body: %w", err)
		return "", err
	}

	return string(body), nil
}

func (clusterWatcher *ClusterWatcher) fetchClusterNameFromAWS(providerHostname, providerEndpoint string) (string, error) {
	var token []byte
	client := &http.Client{Timeout: 2 * time.Second}
	req, err := http.NewRequest("PUT", providerHostname+"/latest/api/token", nil)
	if err != nil {
		clusterWatcher.Log.Warnf("failed to create request for fetching token: %w, check provider host name", err)
		return "", err
	}
	req.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "21600")

	resp, err := client.Do(req)
	if err != nil {
		clusterWatcher.Log.Warnf("error making request: %w", err)
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		token, err = io.ReadAll(resp.Body)
		if err != nil {
			clusterWatcher.Log.Warnf("failed to read token: %d", err)
			return "", err
		}
	}

	// Fetch the EKS cluster name from user data
	url := providerHostname + providerEndpoint
	req, err = http.NewRequest("GET", url, nil)
	client = &http.Client{Timeout: 2 * time.Second}
	if err != nil {
		clusterWatcher.Log.Warnf("failed to create request for fetching metadata: %w, check provider host name and endpoint", err)
		return "", err
	}
	req.Header.Set("X-aws-ec2-metadata-token", string(token))

	resp, err = client.Do(req)
	if err != nil {
		clusterWatcher.Log.Warnf("error making request: %w", err)
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		clusterWatcher.Log.Warnf("failed to fetch from metadata, status code: %d", resp.StatusCode)
		return "", err
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		clusterWatcher.Log.Warnf("failed to read metadata: %d", err)
		return "", err
	}

	// Extract EKS cluster name
	re := regexp.MustCompile(`/etc/eks/bootstrap\.sh (\S+)`)
	match := re.FindStringSubmatch(string(body))
	if len(match) > 0 {
		return match[1], nil
	}

	return "", err
}

func (clusterWatcher *ClusterWatcher) GetClusterName(providerHostname, providerEndpoint string) string {
	provider, pHostname, pEndpoint := clusterWatcher.getProvider(ProviderHostname, providerEndpoint)
	if provider == "gke" {
		clusterWatcher.Log.Infof("Provider is GKE")
		if clusterName, err := clusterWatcher.fetchClusterNameFromGKE(pHostname, pEndpoint); err != nil {
			clusterWatcher.Log.Warnf("Cannot fetch cluster name for GKE %s", err.Error())
		} else {
			return clusterName
		}
	} else if provider == "eks" {
		clusterWatcher.Log.Infof("Provider is EKS")
		if clusterName, err := clusterWatcher.fetchClusterNameFromAWS(pHostname, pEndpoint); err != nil {
			clusterWatcher.Log.Warnf("Cannot fetch cluster name for EKS %s", err.Error())
		} else {
			return clusterName
		}
	}

	return "default"
}

func (clusterWatcher *ClusterWatcher) WatchRequiredResources() {
	var caCert, tlsCrt, tlsKey *bytes.Buffer
	var kGenErr, err, installErr error
	RotateTls := false
	srvAccs := []*corev1.ServiceAccount{
		addOwnership(deployments.GetServiceAccount(common.Namespace)).(*corev1.ServiceAccount),
		addOwnership(deployments.GetRelayServiceAccount(common.Namespace)).(*corev1.ServiceAccount),
		addOwnership(deployments.GetKubeArmorControllerServiceAccount(common.Namespace)).(*corev1.ServiceAccount),
		addOwnership(genSnitchServiceAccount()).(*corev1.ServiceAccount),
	}
	clusterRoles := []*rbacv1.ClusterRole{
		addOwnership(genSnitchRole()).(*rbacv1.ClusterRole),
		addOwnership(deployments.GetRelayClusterRole()).(*rbacv1.ClusterRole),
	}
	controllerClusterRole := addOwnership(deployments.GetKubeArmorControllerClusterRole()).(*rbacv1.ClusterRole)
	if annotateExisting {
		controllerClusterRole.Rules = append(controllerClusterRole.Rules, []rbacv1.PolicyRule{
			{
				APIGroups: []string{"apps"},
				Resources: []string{"deployments", "statefulsets", "daemonsets", "replicasets"},
				Verbs:     []string{"get", "update"},
			},
		}...)
	}
	clusterRoles = append(clusterRoles, controllerClusterRole)

	kaClusterRole := addOwnership(deployments.GetClusterRole()).(*rbacv1.ClusterRole)
	if annotateResource {
		kaClusterRole.Rules = append(kaClusterRole.Rules, []rbacv1.PolicyRule{
			{
				APIGroups: []string{"apps"},
				Resources: []string{"deployments", "replicasets", "daemonsets", "statefulsets"},
				Verbs:     []string{"patch", "update"},
			},
			{
				APIGroups: []string{"batch"},
				Resources: []string{"jobs", "cronjobs"},
				Verbs:     []string{"patch", "update"},
			},
		}...)
	}
	clusterRoles = append(clusterRoles, kaClusterRole)

	clusterRoleBindings := []*rbacv1.ClusterRoleBinding{
		addOwnership(deployments.GetClusterRoleBinding(common.Namespace)).(*rbacv1.ClusterRoleBinding),
		addOwnership(deployments.GetRelayClusterRoleBinding(common.Namespace)).(*rbacv1.ClusterRoleBinding),
		addOwnership(deployments.GetKubeArmorControllerClusterRoleBinding(common.Namespace)).(*rbacv1.ClusterRoleBinding),
		addOwnership(genSnitchRoleBinding()).(*rbacv1.ClusterRoleBinding),
	}
	roles := []*rbacv1.Role{
		addOwnership(deployments.GetKubeArmorControllerLeaderElectionRole(common.Namespace)).(*rbacv1.Role),
	}
	roleBindings := []*rbacv1.RoleBinding{
		addOwnership(deployments.GetKubeArmorControllerLeaderElectionRoleBinding(common.Namespace)).(*rbacv1.RoleBinding),
	}

	kubearmorControllerWebhookSvc := deployments.GetKubeArmorControllerWebhookService(common.Namespace)
	kubearmorControllerWebhookSvc.Spec.Ports[0].TargetPort = intstr.FromInt(int(common.KubeArmorControllerPort))
	svcs := []*corev1.Service{

		addOwnership(kubearmorControllerWebhookSvc).(*corev1.Service),
		addOwnership(deployments.GetRelayService(common.Namespace)).(*corev1.Service),
	}
	// Install CRDs
	ksp := crds.GetKspCRD()
	ksp = addOwnership(ksp).(extv1.CustomResourceDefinition)
	if _, err := clusterWatcher.ExtClient.ApiextensionsV1().CustomResourceDefinitions().Create(context.Background(), &ksp, metav1.CreateOptions{}); err != nil && !metav1errors.IsAlreadyExists(err) {
		if !isAlreadyExists(err) {
			installErr = err
			clusterWatcher.Log.Warnf("Cannot install Ksp CRD, error=%s", err.Error())
		}
	}
	hsp := crds.GetHspCRD()
	hsp = addOwnership(hsp).(extv1.CustomResourceDefinition)
	if _, err := clusterWatcher.ExtClient.ApiextensionsV1().CustomResourceDefinitions().Create(context.Background(), &hsp, metav1.CreateOptions{}); err != nil && !metav1errors.IsAlreadyExists(err) {
		if !isAlreadyExists(err) {
			installErr = err
			clusterWatcher.Log.Warnf("Cannot install Hsp CRD, error=%s", err.Error())
		}
	}
	csp := crds.GetCspCRD()
	csp = addOwnership(csp).(extv1.CustomResourceDefinition)
	if _, err := clusterWatcher.ExtClient.ApiextensionsV1().CustomResourceDefinitions().Create(context.Background(), &csp, metav1.CreateOptions{}); err != nil && !metav1errors.IsAlreadyExists(err) {
		if !isAlreadyExists(err) {
			installErr = err
			clusterWatcher.Log.Warnf("Cannot install Csp CRD, error=%s", err.Error())
		}
	}
	// kubearmor-controller and relay-server deployments
	controller := deployments.GetKubeArmorControllerDeployment(common.Namespace)

	relayServer := deployments.GetRelayDeployment(common.Namespace)
	// update args, imagePullSecrets and tolerations
	UpdateArgsIfDefinedAndUpdated(&controller.Spec.Template.Spec.Containers[0].Args, common.KubeArmorControllerArgs)

	// add annotateExisting flag to controller args
	if annotateExisting {
		UpdateArgsIfDefinedAndUpdated(&controller.Spec.Template.Spec.Containers[0].Args, []string{"annotateExisting=true"})
	}

	UpdateImagePullSecretsIfDefinedAndUpdated(&controller.Spec.Template.Spec.ImagePullSecrets, common.KubeArmorControllerImagePullSecrets)
	UpdateTolerationsIfDefinedAndUpdated(&controller.Spec.Template.Spec.Tolerations, common.KubeArmorControllerTolerations)
	if len(controller.Spec.Template.Spec.ImagePullSecrets) < 1 {
		updateImagePullSecretFromGlobal(common.GlobalImagePullSecrets, &controller.Spec.Template.Spec.ImagePullSecrets)
	}
	if len(controller.Spec.Template.Spec.Tolerations) < 1 {
		updateTolerationFromGlobal(common.GlobalTolerations, &controller.Spec.Template.Spec.Tolerations)
	}
	UpdateArgsIfDefinedAndUpdated(&relayServer.Spec.Template.Spec.Containers[0].Args, common.KubeArmorRelayArgs)
	UpdateImagePullSecretsIfDefinedAndUpdated(&relayServer.Spec.Template.Spec.ImagePullSecrets, common.KubeArmorControllerImagePullSecrets)
	UpdateTolerationsIfDefinedAndUpdated(&relayServer.Spec.Template.Spec.Tolerations, common.KubeArmorControllerTolerations)
	if len(relayServer.Spec.Template.Spec.ImagePullSecrets) < 1 {
		updateImagePullSecretFromGlobal(common.GlobalImagePullSecrets, &relayServer.Spec.Template.Spec.ImagePullSecrets)
	}
	if len(relayServer.Spec.Template.Spec.Tolerations) < 1 {
		updateTolerationFromGlobal(common.GlobalTolerations, &relayServer.Spec.Template.Spec.Tolerations)
	}
	// update relay env vars
	relayServer.Spec.Template.Spec.Containers[0].Env = []corev1.EnvVar{
		{
			Name:  "ENABLE_STDOUT_LOGS",
			Value: common.KubearmorRelayEnvMap[common.EnableStdOutLogs],
		},
		{
			Name:  "ENABLE_STDOUT_ALERTS",
			Value: common.KubearmorRelayEnvMap[common.EnableStdOutAlerts],
		},
		{
			Name:  "ENABLE_STDOUT_MSGS",
			Value: common.KubearmorRelayEnvMap[common.EnableStdOutMsgs],
		},
		{
			Name:  "ENABLE_DASHBOARDS",
			Value: strconv.FormatBool(common.Adapter.ElasticSearch.Enabled),
		},
		{
			Name:  "ES_URL",
			Value: common.Adapter.ElasticSearch.Url,
		},
		{
			Name:  "ES_ALERTS_INDEX",
			Value: common.Adapter.ElasticSearch.AlertsIndexName,
		},
		{
			Name: "ES_USERNAME",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: common.Adapter.ElasticSearch.Auth.SecretName,
					},
					Key:      common.Adapter.ElasticSearch.Auth.UserNameKey,
					Optional: &common.Pointer2True,
				},
			},
		},
		{
			Name: "ES_PASSWORD",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: common.Adapter.ElasticSearch.Auth.SecretName,
					},
					Key:      common.Adapter.ElasticSearch.Auth.PasswordKey,
					Optional: &common.Pointer2True,
				},
			},
		},
	}

	ElasticSearchAdapterCaVolume := []corev1.Volume{
		{
			Name: "elastic-ca",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: common.Adapter.ElasticSearch.Auth.CAcertSecretName,
				},
			},
		},
	}

	ElasticSearchAdapterCaVolumeMount := []corev1.VolumeMount{
		{
			Name:      "elastic-ca",
			MountPath: common.ElasticSearchAdapterCaCertPath,
		},
	}

	if common.Adapter.ElasticSearch.Auth.CAcertSecretName != "" {
		relayServer.Spec.Template.Spec.Containers[0].Env = append(relayServer.Spec.Template.Spec.Containers[0].Env, corev1.EnvVar{
			Name:  "ES_CA_CERT_PATH",
			Value: common.ElasticSearchAdapterCaCertPath + "/" + common.Adapter.ElasticSearch.Auth.CaCertKey,
		})

		common.AddOrRemoveVolume(&ElasticSearchAdapterCaVolume, &relayServer.Spec.Template.Spec.Volumes, common.AddAction)
		common.AddOrRemoveVolumeMount(&ElasticSearchAdapterCaVolumeMount, &relayServer.Spec.Template.Spec.Containers[0].VolumeMounts, common.AddAction)
	} else {
		common.AddOrRemoveVolume(&ElasticSearchAdapterCaVolume, &relayServer.Spec.Template.Spec.Volumes, common.DeleteAction)
		common.AddOrRemoveVolumeMount(&ElasticSearchAdapterCaVolumeMount, &relayServer.Spec.Template.Spec.Containers[0].VolumeMounts, common.DeleteAction)
	}

	if common.Adapter.ElasticSearch.Auth.AllowTlsInsecure {
		relayServer.Spec.Template.Spec.Containers[0].Env = append(relayServer.Spec.Template.Spec.Containers[0].Env, corev1.EnvVar{
			Name:  "ES_ALLOW_INSECURE_TLS",
			Value: "true",
		})
	}
	if common.EnableTls {
		relayServer.Spec.Template.Spec.Containers[0].VolumeMounts =
			append(relayServer.Spec.Template.Spec.Containers[0].VolumeMounts, common.KubeArmorRelayTlsVolumeMount...)
		relayServer.Spec.Template.Spec.Volumes =
			append(relayServer.Spec.Template.Spec.Volumes, common.KubeArmorRelayTlsVolume...)
		common.AddOrReplaceArg("-tlsEnabled=true", "-tlsEnabled=false", &relayServer.Spec.Template.Spec.Containers[0].Args)
	} else {
		common.AddOrReplaceArg("-tlsEnabled=false", "-tlsEnabled=true", &relayServer.Spec.Template.Spec.Containers[0].Args)
	}

	// update images
	containers := &controller.Spec.Template.Spec.Containers
	for i, container := range *containers {
		if container.Name == "manager" {
			(*containers)[i].Image = common.GetApplicationImage(common.KubeArmorControllerName)
			(*containers)[i].ImagePullPolicy = corev1.PullPolicy(common.KubeArmorControllerImagePullPolicy)
		}
	}
	relayServer.Spec.Template.Spec.Containers[0].Image = common.GetApplicationImage(common.KubeArmorRelayName)
	relayServer.Spec.Template.Spec.Containers[0].ImagePullPolicy = corev1.PullPolicy(common.KubeArmorRelayImagePullPolicy)
	deploys := []*appsv1.Deployment{
		addOwnership(relayServer).(*appsv1.Deployment),
	}

	// kubearmor configmap
	configmap := addOwnership(deployments.GetKubearmorConfigMap(common.Namespace, deployments.KubeArmorConfigMapName)).(*corev1.ConfigMap)
	configmap.Data = common.ConfigMapData
	configmap.Data["cluster"] = clusterWatcher.GetClusterName(ProviderHostname, ProviderEndpoint)

	for {
		caCert, tlsCrt, tlsKey, kGenErr = common.GeneratePki(common.Namespace, deployments.KubeArmorControllerWebhookServiceName)
		if kGenErr == nil {
			break
		}
		clusterWatcher.Log.Infof("Couldn't generate TLS secret, re-trying in 3 seconds ...")
		time.Sleep(3 * time.Second)
	}

	tlsCertSecrets := []*corev1.Secret{}

	if common.EnableTls {
		secrets, _ := certGen.GetAllTlsCertSecrets()
		for _, s := range secrets {
			tlsCertSecrets = append(tlsCertSecrets, addOwnership(s).(*corev1.Secret))
		}
	}

	secret := deployments.GetKubeArmorControllerTLSSecret(common.Namespace, caCert.String(), tlsCrt.String(), tlsKey.String())
	secret = addOwnership(secret).(*corev1.Secret)
	mutationhook := deployments.GetKubeArmorControllerMutationAdmissionConfiguration(common.Namespace, caCert.Bytes())
	mutationhook = addOwnership(mutationhook).(*v1.MutatingWebhookConfiguration)
	var caInK8sSecret []byte
	for {
		for _, srvAcc := range srvAccs {
			_, err = clusterWatcher.Client.CoreV1().ServiceAccounts(common.Namespace).Get(context.Background(), srvAcc.Name, metav1.GetOptions{})
			if isNotfound(err) {
				clusterWatcher.Log.Infof("Creating service account %s", srvAcc.Name)
				_, err := clusterWatcher.Client.CoreV1().ServiceAccounts(common.Namespace).Create(context.Background(), srvAcc, metav1.CreateOptions{})
				if err != nil {
					installErr = err
					clusterWatcher.Log.Warnf("Cannot create service account %s, error=%s", srvAcc.Name, err.Error())
				}

			}
		}

		//rbac
		for _, role := range roles {
			_, err = clusterWatcher.Client.RbacV1().Roles(common.Namespace).Get(context.Background(), role.Name, metav1.GetOptions{})
			if isNotfound(err) {
				clusterWatcher.Log.Infof("Creating role %s", role.Name)
				_, err := clusterWatcher.Client.RbacV1().Roles(common.Namespace).Create(context.Background(), role, metav1.CreateOptions{})
				if err != nil {
					installErr = err
					clusterWatcher.Log.Warnf("Cannot create role %s, error=%s", role.Name, err.Error())
				}
			}
		}

		for _, binding := range roleBindings {
			_, err = clusterWatcher.Client.RbacV1().RoleBindings(common.Namespace).Get(context.Background(), binding.Name, metav1.GetOptions{})
			if isNotfound(err) {
				clusterWatcher.Log.Infof("Creating role binding %s", binding.Name)
				_, err := clusterWatcher.Client.RbacV1().RoleBindings(common.Namespace).Create(context.Background(), binding, metav1.CreateOptions{})
				if err != nil {
					installErr = err
					clusterWatcher.Log.Warnf("Cannot create role binding %s, error=%s", binding.Name, err.Error())
				}
			}
		}

		for _, clusterRole := range clusterRoles {
			role, err := clusterWatcher.Client.RbacV1().ClusterRoles().Get(context.Background(), clusterRole.Name, metav1.GetOptions{})
			if isNotfound(err) {
				clusterWatcher.Log.Infof("Creating cluster role %s", clusterRole.Name)
				_, err := clusterWatcher.Client.RbacV1().ClusterRoles().Create(context.Background(), clusterRole, metav1.CreateOptions{})
				if err != nil {
					installErr = err
					clusterWatcher.Log.Warnf("Cannot create cluster role %s, error=%s", clusterRole.Name, err.Error())
				}
			} else if err == nil && !reflect.DeepEqual(role.Rules, clusterRole.Rules) {
				// update clusterroles if there's a change in rules
				clusterWatcher.Log.Infof("Updating cluster role %s", clusterRole.Name)
				_, err := clusterWatcher.Client.RbacV1().ClusterRoles().Update(context.Background(), clusterRole, metav1.UpdateOptions{})
				if err != nil {
					installErr = err
					clusterWatcher.Log.Warnf("Cannot update cluster role %s, error=%s", clusterRole.Name, err.Error())
				}
			}
		}

		for _, binding := range clusterRoleBindings {
			_, err = clusterWatcher.Client.RbacV1().ClusterRoleBindings().Get(context.Background(), binding.Name, metav1.GetOptions{})
			if isNotfound(err) {
				clusterWatcher.Log.Infof("Creating cluster role binding %s", binding.Name)
				_, err := clusterWatcher.Client.RbacV1().ClusterRoleBindings().Create(context.Background(), binding, metav1.CreateOptions{})
				if err != nil {
					installErr = err
					clusterWatcher.Log.Warnf("Cannot create cluster role binding %s, error=%s", binding.Name, err.Error())
				}
			}
		}

		//configmap
		_, err := clusterWatcher.Client.CoreV1().ConfigMaps(common.Namespace).Get(context.Background(), configmap.Name, metav1.GetOptions{})
		if isNotfound(err) {
			clusterWatcher.Log.Infof("Creating ConfigMap %s", configmap.Name)
			_, err := clusterWatcher.Client.CoreV1().ConfigMaps(common.Namespace).Create(context.Background(), configmap, metav1.CreateOptions{})
			if err != nil {
				installErr = err
				clusterWatcher.Log.Warnf("Cannot create configmap %s, error=%s", configmap.Name, err.Error())
			}
		}

		// svcs
		for _, svc := range svcs {
			_, err = clusterWatcher.Client.CoreV1().Services(common.Namespace).Get(context.Background(), svc.Name, metav1.GetOptions{})
			if isNotfound(err) {
				clusterWatcher.Log.Infof("Creating service %s", svc.Name)
				_, err := clusterWatcher.Client.CoreV1().Services(common.Namespace).Create(context.Background(), svc, metav1.CreateOptions{})
				if err != nil {
					installErr = err
					clusterWatcher.Log.Warnf("Cannot create service %s, error=%s", svc.Name, err.Error())
				}
			}
		}

		// watchTlsState
		clusterWatcher.WatchTlsState(common.GetTlsState())

		//secret
		s, err := clusterWatcher.Client.CoreV1().Secrets(common.Namespace).Get(context.Background(), secret.Name, metav1.GetOptions{})
		if isNotfound(err) {
			clusterWatcher.Log.Infof("Creating secret %s", secret.Name)
			_, err := clusterWatcher.Client.CoreV1().Secrets(common.Namespace).Create(context.Background(), secret, metav1.CreateOptions{})
			if err != nil {
				installErr = err
				clusterWatcher.Log.Warnf("Cannot create secret %s, error=%s", secret.Name, err.Error())
			} else {
				caInK8sSecret = secret.Data["ca.crt"]
			}
		} else if err == nil {
			caInK8sSecret = s.Data["ca.crt"]
		}

		// deploy
		for _, deploy := range deploys {
			_, err := clusterWatcher.Client.AppsV1().Deployments(common.Namespace).Get(context.Background(), deploy.Name, metav1.GetOptions{})
			if isNotfound(err) {
				clusterWatcher.Log.Infof("Creating deployment %s", deploy.Name)
				_, err = clusterWatcher.Client.AppsV1().Deployments(common.Namespace).Create(context.Background(), deploy, metav1.CreateOptions{})
				if err != nil {
					installErr = err
					clusterWatcher.Log.Warnf("Cannot create deployment %s, error=%s", deploy.Name, err.Error())
				}
			}
		}

		areAllNodeProcessed := clusterWatcher.AreAllNodesProcessed()

		// deploy controller
		if err := clusterWatcher.deployControllerDeployment(controller); err != nil {
			installErr = err
		}

		//mutation webhook
		hook, err := clusterWatcher.Client.AdmissionregistrationV1().MutatingWebhookConfigurations().Get(context.Background(), mutationhook.Name, metav1.GetOptions{})
		if isNotfound(err) {
			clusterWatcher.Log.Infof("Creating mutation webhook %s", mutationhook.Name)
			_, err = clusterWatcher.Client.AdmissionregistrationV1().MutatingWebhookConfigurations().Create(context.Background(), mutationhook, metav1.CreateOptions{})
			if err != nil {
				installErr = err
				clusterWatcher.Log.Warnf("Cannot create mutation webhook %s, error=%s", mutationhook.Name, err.Error())
			}
		} else if err == nil {
			if !bytes.Equal(hook.Webhooks[0].ClientConfig.CABundle, caInK8sSecret) {
				// rotate
				RotateTls = true
			}
		} else {
			installErr = err
			clusterWatcher.Log.Error(err.Error())
		}

		if err := clusterWatcher.WatchRecommendedPolicies(); err != nil {
			installErr = err
		}

		// update operatingConfigCrd status to Running
		if common.OperatorConfigCrd != nil {
			if installErr != nil {
				installErr = nil
				go clusterWatcher.UpdateCrdStatus(common.OperatorConfigCrd.Name, common.ERROR, common.INSTALLATION_ERR_MSG)
			} else if areAllNodeProcessed {
				go clusterWatcher.UpdateCrdStatus(common.OperatorConfigCrd.Name, common.RUNNING, common.RUNNING_MSG)
			} else {
				go clusterWatcher.UpdateCrdStatus(common.OperatorConfigCrd.Name, common.PENDING, common.PENDING_MSG)
			}
		}

		if RotateTls {
			clusterWatcher.RotateTlsCerts()
			RotateTls = false
		}
		time.Sleep(10 * time.Second)
	}
}

func (clusterWatcher *ClusterWatcher) RotateTlsCerts() {
	var caCert, tlsCrt, tlsKey *bytes.Buffer
	var err error

	origdeploy, err := clusterWatcher.Client.AppsV1().Deployments(common.Namespace).Get(context.Background(), deployments.KubeArmorControllerDeploymentName, metav1.GetOptions{})
	if err != nil {
		clusterWatcher.Log.Warnf("cannot get controller deployment, error=%s", err.Error())
	}

	caCert, tlsCrt, tlsKey, _ = common.GeneratePki(common.Namespace, deployments.KubeArmorControllerWebhookServiceName)
	replicas := origdeploy.Spec.Replicas

	// TODO: Keep CA certificate in k8s secret

	// == CLEANUP ==
	// scale down controller deployment to 0
	controllerDeployment := deployments.GetKubeArmorControllerDeployment(common.Namespace)
	controllerDeployment = addOwnership(controllerDeployment).(*appsv1.Deployment)
	zeroReplicas := int32(0)
	controllerDeployment.Spec.Replicas = &zeroReplicas
	if _, err := clusterWatcher.Client.AppsV1().Deployments(common.Namespace).Update(context.Background(), controllerDeployment, metav1.UpdateOptions{}); err != nil {
		clusterWatcher.Log.Warnf("cannot scale down controller %s, error=%s", controllerDeployment.Name, err.Error())
	}
	// delete mutation webhook configuration
	mutationWebhook := deployments.GetKubeArmorControllerMutationAdmissionConfiguration(common.Namespace, caCert.Bytes())
	mutationWebhook = addOwnership(mutationWebhook).(*v1.MutatingWebhookConfiguration)
	if err := clusterWatcher.Client.AdmissionregistrationV1().MutatingWebhookConfigurations().Delete(context.Background(), mutationWebhook.Name, metav1.DeleteOptions{}); err != nil {
		clusterWatcher.Log.Warnf("cannot delete mutation webhook %s, error=%s", mutationWebhook.Name, err.Error())
	}
	// == ROTATE ==
	// update controller tls secret
	controllerSecret := deployments.GetKubeArmorControllerTLSSecret(common.Namespace, caCert.String(), tlsCrt.String(), tlsKey.String())
	controllerSecret = addOwnership(controllerSecret).(*corev1.Secret)
	if _, err := clusterWatcher.Client.CoreV1().Secrets(common.Namespace).Update(context.Background(), controllerSecret, metav1.UpdateOptions{}); err != nil {
		clusterWatcher.Log.Warnf("cannot update controller tls secret %s, error=%s", controllerSecret.Name, err.Error())
	}
	// == ROLLOUT ==
	// create mutation webhook configuration
	if _, err := clusterWatcher.Client.AdmissionregistrationV1().MutatingWebhookConfigurations().Create(context.Background(), mutationWebhook, metav1.CreateOptions{}); err != nil {
		clusterWatcher.Log.Warnf("Cannot create mutation webhook %s, error=%s", mutationWebhook.Name, err.Error())
	}
	// scale up controller deployment to previous settings
	controllerDeployment.Spec.Replicas = replicas
	if _, err := clusterWatcher.Client.AppsV1().Deployments(common.Namespace).Update(context.Background(), controllerDeployment, metav1.UpdateOptions{}); err != nil {
		clusterWatcher.Log.Warnf("cannot scale down controller %s, error=%s", controllerDeployment.Name, err.Error())
	}
	clusterWatcher.Log.Info("Tls rotation completed")
}
