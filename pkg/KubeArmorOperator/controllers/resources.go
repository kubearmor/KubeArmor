package controllers

import (
	"bytes"
	"context"
	"strings"
	"time"

	deployments "github.com/kubearmor/KubeArmor/deployments/get"
	"github.com/kubearmor/KubeArmor/pkg/KubeArmorOperator/common"
	v1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func generateDaemonset(name, enforcer, runtime, socket, runtimeStorage string) *appsv1.DaemonSet {
	enforcerVolumes, enforcerVolumeMounts := genEnforcerVolumes(enforcer)
	runtimeVolumes, runtimeVolumeMounts := genRuntimeVolumes(runtime, socket, runtimeStorage)
	vols := []corev1.Volume{}
	volMnts := []corev1.VolumeMount{}
	vols = append(vols, enforcerVolumes...)
	vols = append(vols, runtimeVolumes...)
	vols = append(vols, common.CommonVolumes...)
	volMnts = append(volMnts, enforcerVolumeMounts...)
	volMnts = append(volMnts, runtimeVolumeMounts...)
	volMnts = append(volMnts, common.CommonVolumesMount...)

	daemonset := deployments.GenerateDaemonSet("generic", common.Namespace)
	daemonset.Name = name
	labels := map[string]string{
		common.EnforcerLabel:       enforcer,
		common.RuntimeLabel:        runtime,
		common.RuntimeStorageLabel: runtimeStorage,
		common.SocketLabel:         socket,
		common.OsLabel:             "linux",
	}
	for key, value := range labels {
		daemonset.Spec.Template.Spec.NodeSelector[key] = value
		daemonset.Spec.Template.Spec.NodeSelector[key] = value
		daemonset.Spec.Selector.MatchLabels[key] = value
	}
	daemonset.Spec.Template.Spec.ServiceAccountName = "kubearmor"
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
	daemonset.Spec.Template.Spec.Volumes = vols
	daemonset.Spec.Template.Spec.InitContainers[0].VolumeMounts = common.CommonVolumesMount
	daemonset.Spec.Template.Spec.Containers[0].VolumeMounts = volMnts
	daemonset.Spec.Template.Spec.Containers[0].Args = append(daemonset.Spec.Template.Spec.Containers[0].Args, "-criSocket=unix:///"+strings.ReplaceAll(socket, "_", "/"))
	daemonset = addOwnership(daemonset).(*appsv1.DaemonSet)
	return daemonset
}

func genEnforcerVolumes(enforcer string) (vol []corev1.Volume, volMnt []corev1.VolumeMount) {
	for _, e := range strings.Split(enforcer, ".") {
		vol = append(vol, common.EnforcerVolumes[e]...)
		volMnt = append(volMnt, common.EnforcerVolumesMounts[e]...)
	}
	return
}

func genRuntimeVolumes(runtime, runtimeSocket, runtimeStorage string) (vol []corev1.Volume, volMnt []corev1.VolumeMount) {
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
			volMnt = append(volMnt, corev1.VolumeMount{
				Name:      runtime + "-socket",
				MountPath: socket,
				ReadOnly:  true,
			})
			break
		}
	}
	// lookup runtime storage location

	for _, storageLocation := range common.RuntimeStorageVolumes[runtime] {
		if strings.ReplaceAll(runtimeSocket[1:], "/", "_") == runtimeStorage {
			vol = append(vol, corev1.Volume{
				Name: runtime + "-storage",
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{
						Path: storageLocation,
						Type: &common.HostPathDirectory,
					},
				},
			})
			volMnt = append(volMnt, corev1.VolumeMount{
				Name:      runtime + "-storage",
				MountPath: storageLocation,
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
	job = *addOwnership(&job).(*batchv1.Job)
	ttls := int32(100)
	job.GenerateName = "kubearmor-snitch-"

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
						Image: common.OperatorImage,
						Command: []string{
							"/snitch",
						},
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
						},
					},
				},
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
				},
			},
		},
	}
	return &job
}

func isNotfound(err error) bool {
	return err != nil && strings.Contains(err.Error(), "not found")
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
	}
	return obj
}

func (clusterWatcher *ClusterWatcher) WatchRequiredResources() {
	var caCert, tlsCrt, tlsKey *bytes.Buffer
	var kGenErr, err error
	RotateTls := false
	FirstRun := true
	srvAccs := []*corev1.ServiceAccount{
		addOwnership(deployments.GetServiceAccount(common.Namespace)).(*corev1.ServiceAccount),
		addOwnership(genSnitchServiceAccount()).(*corev1.ServiceAccount),
	}
	bindings := []*rbacv1.ClusterRoleBinding{
		addOwnership(deployments.GetClusterRoleBinding(common.Namespace)).(*rbacv1.ClusterRoleBinding),
		addOwnership(genSnitchRoleBinding()).(*rbacv1.ClusterRoleBinding),
	}
	svcs := []*corev1.Service{
		addOwnership(deployments.GetKubeArmorControllerService(common.Namespace)).(*corev1.Service),
		addOwnership(deployments.GetKubeArmorControllerService(common.Namespace)).(*corev1.Service),
	}
	deploys := []*appsv1.Deployment{
		addOwnership(deployments.GetKubeArmorControllerDeployment(common.Namespace)).(*appsv1.Deployment),
		addOwnership(deployments.GetRelayDeployment(common.Namespace)).(*appsv1.Deployment),
	}

	role := addOwnership(genSnitchRole()).(*rbacv1.ClusterRole)
	for {
		caCert, tlsCrt, tlsKey, kGenErr = common.GeneratePki(common.Namespace, deployments.KubeArmorControllerServiceName)
		if kGenErr == nil {
			break
		}
		clusterWatcher.Log.Infof("Couldnt generate TLS secret, re-trying in 3 seconds ...")
		time.Sleep(3 * time.Second)
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
					clusterWatcher.Log.Warnf("Cannot create service account %s, error=%s", srvAcc.Name, err.Error())
				}

			}
		}

		//rbac
		_, err = clusterWatcher.Client.RbacV1().ClusterRoles().Get(context.Background(), role.Name, metav1.GetOptions{})
		if isNotfound(err) {
			clusterWatcher.Log.Infof("Creating role %s", role.Name)
			_, err := clusterWatcher.Client.RbacV1().ClusterRoles().Create(context.Background(), role, metav1.CreateOptions{})
			if err != nil {
				clusterWatcher.Log.Warnf("Cannot create cluster role %s, error=%s", role.Name, err.Error())
			}
		}

		for _, binding := range bindings {
			_, err = clusterWatcher.Client.RbacV1().ClusterRoleBindings().Get(context.Background(), binding.Name, metav1.GetOptions{})
			if isNotfound(err) {
				clusterWatcher.Log.Infof("Creating cluster role binding %s", binding.Name)
				_, err := clusterWatcher.Client.RbacV1().ClusterRoleBindings().Create(context.Background(), binding, metav1.CreateOptions{})
				if err != nil {
					clusterWatcher.Log.Warnf("Cannot create cluster role binding %s, error=%s", binding.Name, err.Error())
				}
			}
		}

		// svcs
		for _, svc := range svcs {
			_, err = clusterWatcher.Client.CoreV1().Services(common.Namespace).Get(context.Background(), svc.Name, metav1.GetOptions{})
			if isNotfound(err) {
				clusterWatcher.Log.Infof("Creating service %s", svc.Name)
				_, err := clusterWatcher.Client.CoreV1().Services(common.Namespace).Create(context.Background(), svc, metav1.CreateOptions{})
				if err != nil {
					clusterWatcher.Log.Warnf("Cannot create service %s, error=%s", svc.Name, err.Error())
				}
			}
		}

		//secret
		s, err := clusterWatcher.Client.CoreV1().Secrets(common.Namespace).Get(context.Background(), secret.Name, metav1.GetOptions{})
		if isNotfound(err) {
			clusterWatcher.Log.Infof("Creating secret %s", secret.Name)
			_, err := clusterWatcher.Client.CoreV1().Secrets(common.Namespace).Create(context.Background(), secret, metav1.CreateOptions{})
			if err != nil {
				clusterWatcher.Log.Warnf("Cannot create secret %s, error=%s", secret.Name, err.Error())
			} else {
				RotateTls = true && !FirstRun
				if !FirstRun {
					clusterWatcher.Log.Warnf("Secret was created, rotating TLS secrets")
				}
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
					clusterWatcher.Log.Warnf("Cannot create deployment %s, error=%s", deploy.Name, err.Error())
				}
			}
		}

		//mutation webhook
		hook, err := clusterWatcher.Client.AdmissionregistrationV1().MutatingWebhookConfigurations().Get(context.Background(), mutationhook.Name, metav1.GetOptions{})
		if isNotfound(err) {
			clusterWatcher.Log.Infof("Creating mutation webhook %s", mutationhook.Name)
			_, err = clusterWatcher.Client.AdmissionregistrationV1().MutatingWebhookConfigurations().Create(context.Background(), mutationhook, metav1.CreateOptions{})
			if err != nil {
				clusterWatcher.Log.Warnf("Cannot create mutation webhook %s, error=%s", mutationhook.Name, err.Error())
			}
		} else if err == nil {
			if !bytes.Equal(hook.Webhooks[0].ClientConfig.CABundle, caInK8sSecret) {
				// rotate
				RotateTls = true && !FirstRun
				if !FirstRun {
					clusterWatcher.Log.Warnf("mutation CA cert does not match secret CA cert, rotating tls secrets")
				}
			}
		} else {
			clusterWatcher.Log.Error(err.Error())
		}

		if RotateTls {
			clusterWatcher.RotateTlsCerts()
			RotateTls = false
		}
		if FirstRun {
			FirstRun = false
		}
		time.Sleep(10 * time.Second)
	}
}

func (clusterWatcher *ClusterWatcher) RotateTlsCerts() {
	var suffix string
	var caCert, tlsCrt, tlsKey *bytes.Buffer
	var err error
	retries := 0
	for {
		if retries == 3 {
			return
		}
		retries++
		suffix, err = common.GetFreeRandSuffix(clusterWatcher.Client, common.Namespace)
		if err == nil {
			clusterWatcher.Log.Infof("Using suffix %s for all new temorary resources", suffix)
			break
		}
		clusterWatcher.Log.Infof("Cannot find a suffix, err=%s, retrying in 3 seconds...", err.Error())
		time.Sleep(3 * time.Second)
	}
	serviceName := deployments.KubeArmorControllerServiceName + "-" + suffix
	for {
		caCert, tlsCrt, tlsKey, err = common.GeneratePki(common.Namespace, serviceName)
		if err == nil {
			break
		}
		clusterWatcher.Log.Infof("Could'nt generate TLS secret, retrying in 3 seconds")
		time.Sleep(3 * time.Second)
	}
	tmpsecret := deployments.GetKubeArmorControllerTLSSecret(common.Namespace, caCert.String(), tlsCrt.String(), tlsKey.String())
	tmpsecret = addOwnership(tmpsecret).(*corev1.Secret)
	tmpsecret.Name = tmpsecret.GetName() + "-" + suffix
	_, err = clusterWatcher.Client.CoreV1().Secrets(common.Namespace).Create(context.Background(), tmpsecret, metav1.CreateOptions{})
	if err != nil {
		clusterWatcher.Log.Warnf("Cannot create secret %s, error=%s", tmpsecret.Name, err.Error())
	}
	tmpdeploy := deployments.GetKubeArmorControllerDeployment(common.Namespace)
	tmpdeploy = addOwnership(tmpdeploy).(*appsv1.Deployment)
	tmpdeploy.Name = tmpdeploy.GetName() + "-" + suffix
	for i, s := range tmpdeploy.Spec.Template.Spec.Volumes {
		if s.Name == "cert" {
			s.Secret.SecretName = tmpsecret.GetName()
			tmpdeploy.Spec.Template.Spec.Volumes[i] = s
			break
		}
	}
	selectLabels := tmpdeploy.Spec.Selector.MatchLabels
	selectLabels["kubearmor-app"] = suffix
	tmpdeploy.Spec.Selector.MatchLabels = selectLabels
	origdeploy, _ := clusterWatcher.Client.AppsV1().Deployments(common.Namespace).Get(context.Background(), deployments.KubeArmorControllerDeploymentName, metav1.GetOptions{})
	origdeploy = addOwnership(origdeploy).(*appsv1.Deployment)
	tmpdeploy.Spec.Replicas = origdeploy.Spec.Replicas
	if _, err := clusterWatcher.Client.AppsV1().Deployments(common.Namespace).Create(context.Background(), tmpdeploy, metav1.CreateOptions{}); err != nil {
		clusterWatcher.Log.Warnf("Cannot create deployment %s, error=%s", tmpdeploy.Name, err.Error())
	}

	time.Sleep(10 * time.Second)

	tmpservice := deployments.GetKubeArmorControllerService(common.Namespace)
	tmpservice = addOwnership(tmpservice).(*corev1.Service)
	tmpservice.Name = serviceName
	tmpservice.Spec.Selector = selectLabels
	if _, err := clusterWatcher.Client.CoreV1().Services(common.Namespace).Create(context.Background(), tmpservice, metav1.CreateOptions{}); err != nil {
		clusterWatcher.Log.Warnf("Cannot create deployment %s, error=%s", tmpservice.Name, err.Error())
	}
	tmpmutation := deployments.GetKubeArmorControllerMutationAdmissionConfiguration(common.Namespace, caCert.Bytes())
	mutationName := tmpmutation.Name
	tmpmutation = addOwnership(tmpmutation).(*v1.MutatingWebhookConfiguration)
	tmpmutation.Name = tmpmutation.Name + "-" + suffix
	tmpmutation.Webhooks[0].ClientConfig.Service.Name = tmpservice.GetName()
	if _, err := clusterWatcher.Client.AdmissionregistrationV1().MutatingWebhookConfigurations().Create(context.Background(), tmpmutation, metav1.CreateOptions{}); err != nil {
		clusterWatcher.Log.Warnf("Cannot create mutation webhook %s, error=%s", tmpmutation.Name, err.Error())
	}
	clusterWatcher.Client.AdmissionregistrationV1().MutatingWebhookConfigurations().Delete(context.Background(), mutationName, metav1.DeleteOptions{})
	caCert, tlsCrt, tlsKey, _ = common.GeneratePki(common.Namespace, deployments.KubeArmorControllerServiceName)
	secret := deployments.GetKubeArmorControllerTLSSecret(common.Namespace, caCert.String(), tlsCrt.String(), tlsKey.String())
	secret = addOwnership(secret).(*corev1.Secret)
	clusterWatcher.Client.CoreV1().Secrets(common.Namespace).Update(context.Background(), secret, metav1.UpdateOptions{})

	replicas := int32(0)
	origdeploy.Spec.Replicas = &replicas
	clusterWatcher.Client.AppsV1().Deployments(common.Namespace).Update(context.Background(), origdeploy, metav1.UpdateOptions{})
	time.Sleep(10 * time.Second)
	origdeploy, _ = clusterWatcher.Client.AppsV1().Deployments(common.Namespace).Get(context.Background(), deployments.KubeArmorControllerDeploymentName, metav1.GetOptions{})
	origdeploy = addOwnership(origdeploy).(*appsv1.Deployment)
	origdeploy.Spec.Replicas = tmpdeploy.Spec.Replicas

	clusterWatcher.Client.AppsV1().Deployments(common.Namespace).Update(context.Background(), origdeploy, metav1.UpdateOptions{})
	mutation := deployments.GetKubeArmorControllerMutationAdmissionConfiguration(common.Namespace, caCert.Bytes())
	mutation = addOwnership(mutation).(*v1.MutatingWebhookConfiguration)

	clusterWatcher.Client.AdmissionregistrationV1().MutatingWebhookConfigurations().Create(context.Background(), mutation, metav1.CreateOptions{})

	clusterWatcher.Client.AdmissionregistrationV1().MutatingWebhookConfigurations().Delete(context.Background(), tmpmutation.Name, metav1.DeleteOptions{})
	clusterWatcher.Client.CoreV1().Services(common.Namespace).Delete(context.Background(), tmpservice.Name, metav1.DeleteOptions{})
	clusterWatcher.Client.AppsV1().Deployments(common.Namespace).Delete(context.Background(), tmpdeploy.Name, metav1.DeleteOptions{})
	clusterWatcher.Client.CoreV1().Secrets(common.Namespace).Delete(context.Background(), tmpsecret.Name, metav1.DeleteOptions{})
	clusterWatcher.Log.Info("Tls rotation completed")
}
