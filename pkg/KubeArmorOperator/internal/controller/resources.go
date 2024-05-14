// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package controller

import (
	"bytes"
	"context"
	"fmt"
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
)

func generateDaemonset(name, enforcer, runtime, socket, btfPresent, apparmorfs, seccompPresent string) *appsv1.DaemonSet {
	enforcerVolumes := []corev1.Volume{}
	enforcerVolumeMounts := []corev1.VolumeMount{}
	if !(enforcer == "apparmor" && apparmorfs == "no") {
		enforcerVolumes, enforcerVolumeMounts = genEnforcerVolumes(enforcer)
	}
	runtimeVolumes, runtimeVolumeMounts := genRuntimeVolumes(runtime, socket)
	vols := []corev1.Volume{}
	volMnts := []corev1.VolumeMount{}
	vols = append(vols, enforcerVolumes...)
	vols = append(vols, runtimeVolumes...)
	volMnts = append(volMnts, enforcerVolumeMounts...)
	volMnts = append(volMnts, runtimeVolumeMounts...)
	commonVols := common.CommonVolumes
	commonVolMnts := common.CommonVolumesMount

	if btfPresent == "no" {
		commonVols = append(commonVols, common.BPFVolumes...)
		commonVolMnts = append(commonVolMnts, common.BPFVolumesMount...)
		commonVols = append(commonVols, common.KernelHeaderVolumes...)
		commonVolMnts = append(commonVolMnts, common.KernelHeaderVolumesMount...)
	}
	vols = append(vols, commonVols...)
	volMnts = append(volMnts, commonVolMnts...)
	daemonset := deployments.GenerateDaemonSet("generic", common.Namespace)

	if btfPresent != "no" {
		daemonset.Spec.Template.Spec.InitContainers = []corev1.Container{}
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
	if common.EnableTls {
		vols = append(vols, common.KubeArmorCaVolume...)
		volMnts = append(volMnts, common.KubeArmorCaVolumeMount...)
		common.AddOrReplaceArg("-tlsEnabled=true", "-tlsEnabled=false", &daemonset.Spec.Template.Spec.Containers[0].Args)
	} else {
		common.AddOrReplaceArg("-tlsEnabled=false", "-tlsEnabled=true", &daemonset.Spec.Template.Spec.Containers[0].Args)
	}
	daemonset.Spec.Template.Spec.Volumes = vols
	daemonset.Spec.Template.Spec.Containers[0].VolumeMounts = volMnts
	// update images

	if seccompPresent == "yes" && common.ConfigDefaultSeccompEnabled == "true" {
		daemonset.Spec.Template.Spec.Containers[0].SecurityContext.SeccompProfile = &corev1.SeccompProfile{
			Type:             corev1.SeccompProfileTypeLocalhost,
			LocalhostProfile: &common.SeccompProfile,
		}
		daemonset.Spec.Template.Spec.InitContainers[0].SecurityContext.SeccompProfile = &corev1.SeccompProfile{
			Type:             corev1.SeccompProfileTypeLocalhost,
			LocalhostProfile: &common.SeccompInitProfile,
		}

	}

	daemonset.Spec.Template.Spec.Containers[0].Image = common.GetApplicationImage(common.KubeArmorName)
	daemonset.Spec.Template.Spec.Containers[0].ImagePullPolicy = corev1.PullPolicy(common.KubeArmorImagePullPolicy)

	if btfPresent == "no" {
		daemonset.Spec.Template.Spec.InitContainers[0].VolumeMounts = commonVolMnts
		daemonset.Spec.Template.Spec.InitContainers[0].Image = common.GetApplicationImage(common.KubeArmorInitName)
		daemonset.Spec.Template.Spec.InitContainers[0].ImagePullPolicy = corev1.PullPolicy(common.KubeArmorInitImagePullPolicy)
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

func genRuntimeVolumes(runtime, runtimeSocket string) (vol []corev1.Volume, volMnt []corev1.VolumeMount) {
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
	var HostPathDirectoryOrCreate = corev1.HostPathDirectoryOrCreate
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
								Name:      "rootfs",
								MountPath: PathPrefix,
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
				HostPID:            common.HostPID,
				NodeName:           nodename,
				RestartPolicy:      corev1.RestartPolicyOnFailure,
				ServiceAccountName: common.KubeArmorSnitchRoleName,
				Volumes: []corev1.Volume{
					{
						Name: "rootfs",
						VolumeSource: corev1.VolumeSource{
							HostPath: &corev1.HostPathVolumeSource{
								Path: "/",
								Type: &common.HostPathDirectory,
							},
						},
					},
					{
						Name: "seccomp-path",
						VolumeSource: corev1.VolumeSource{
							HostPath: &corev1.HostPathVolumeSource{
								Path: "/var/lib/kubelet/seccomp",
								Type: &HostPathDirectoryOrCreate,
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
	if common.IfNodeWithSecurtiyFs {
		deployment.Spec.Template.Spec.NodeSelector = map[string]string{
			common.SecurityFsLabel: "yes",
		}
		deployment.Spec.Template.Spec.Containers = deployments.GetKubeArmorControllerDeployment(common.Namespace).Spec.Template.Spec.Containers
	} else {
		deployment.Spec.Template.Spec.NodeSelector = nil
		for i, container := range deployment.Spec.Template.Spec.Containers {
			if container.Name == "manager" {
				for j, mount := range container.VolumeMounts {
					if mount.MountPath == "/sys/kernel/security" {
						deployment.Spec.Template.Spec.Containers[i].VolumeMounts = append(deployment.Spec.Template.Spec.Containers[i].VolumeMounts[:j],
							deployment.Spec.Template.Spec.Containers[i].VolumeMounts[j+1:]...)
					}
				}
			}
		}
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
			(!common.IfNodeWithSecurtiyFs && controller.Spec.Template.Spec.NodeSelector != nil) {
			clusterWatcher.Log.Infof("Updating deployment %s", controller.Name)
			controller.Spec.Template.Spec.NodeSelector = deployment.Spec.Template.Spec.NodeSelector
			controller.Spec.Template.Spec.Containers = deployment.Spec.Template.Spec.Containers
			_, err = clusterWatcher.Client.AppsV1().Deployments(common.Namespace).Update(context.Background(), controller, metav1.UpdateOptions{})
			if err != nil {
				clusterWatcher.Log.Warnf("Cannot update deployment %s, error=%s", deployment.Name, err.Error())
				return err
			}
		}
	}
	return nil
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
		addOwnership(deployments.GetClusterRole()).(*rbacv1.ClusterRole),
		addOwnership(deployments.GetRelayClusterRole()).(*rbacv1.ClusterRole),
		addOwnership(deployments.GetKubeArmorControllerProxyRole()).(*rbacv1.ClusterRole),
		addOwnership(deployments.GetKubeArmorControllerClusterRole()).(*rbacv1.ClusterRole),
	}
	clusterRoleBindings := []*rbacv1.ClusterRoleBinding{
		addOwnership(deployments.GetClusterRoleBinding(common.Namespace)).(*rbacv1.ClusterRoleBinding),
		addOwnership(deployments.GetRelayClusterRoleBinding(common.Namespace)).(*rbacv1.ClusterRoleBinding),
		addOwnership(deployments.GetKubeArmorControllerClusterRoleBinding(common.Namespace)).(*rbacv1.ClusterRoleBinding),
		addOwnership(deployments.GetKubeArmorControllerProxyRoleBinding(common.Namespace)).(*rbacv1.ClusterRoleBinding),
		addOwnership(genSnitchRoleBinding()).(*rbacv1.ClusterRoleBinding),
	}
	roles := []*rbacv1.Role{
		addOwnership(deployments.GetKubeArmorControllerLeaderElectionRole(common.Namespace)).(*rbacv1.Role),
	}
	roleBindings := []*rbacv1.RoleBinding{
		addOwnership(deployments.GetKubeArmorControllerLeaderElectionRoleBinding(common.Namespace)).(*rbacv1.RoleBinding),
	}

	svcs := []*corev1.Service{
		addOwnership(deployments.GetKubeArmorControllerMetricsService(common.Namespace)).(*corev1.Service),
		addOwnership(deployments.GetKubeArmorControllerWebhookService(common.Namespace)).(*corev1.Service),
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
	// kubearmor-controller and relay-server deployments
	controller := deployments.GetKubeArmorControllerDeployment(common.Namespace)
	relayServer := deployments.GetRelayDeployment(common.Namespace)

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
		} else {
			(*containers)[i].Image = common.GetApplicationImage(common.KubeRbacProxyName)
			(*containers)[i].ImagePullPolicy = corev1.PullPolicy(common.KubeRbacProxyImagePullPolicy)
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
			_, err = clusterWatcher.Client.RbacV1().ClusterRoles().Get(context.Background(), clusterRole.Name, metav1.GetOptions{})
			if isNotfound(err) {
				clusterWatcher.Log.Infof("Creating cluster role %s", clusterRole.Name)
				_, err := clusterWatcher.Client.RbacV1().ClusterRoles().Create(context.Background(), clusterRole, metav1.CreateOptions{})
				if err != nil {
					installErr = err
					clusterWatcher.Log.Warnf("Cannot create cluster role %s, error=%s", clusterRole.Name, err.Error())
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
