// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package controller

import (
	"context"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"sync"

	"github.com/kubearmor/KubeArmor/pkg/KubeArmorOperator/defaults"
	"github.com/kubearmor/KubeArmor/pkg/KubeArmorOperator/internal/helm"

	"go.uber.org/zap"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

var (
	informer                 informers.SharedInformerFactory
	operatorDeploymentUID    string
	operatorDeploymentName   string
	snitchPathPrefix         string
	snitchImage              string
	snitchImagePullPolicy    string
	lsmOrder                 string
	operatorWatchedNamespace string
)

// WatcherConfig provides configurations for ClusterWatcher instance
type WatcherConfig struct {
	SnitchImage              string
	SnitchPathPrefix         string
	SnitchImagePullPolicy    string
	LsmOrder                 string
	OperatorWatchedNamespace string
	OperatorDeploymentName   string
	OperatorDeploymentUID    string
}

// ClusterWatcher providers a node watcher that watches for nodes across the cluster
// and probes each node to detect lsm, container runtime, btf support configuration
type ClusterWatcher struct {
	helmController *helm.Controller
	nodes          map[string]node
	nodesLock      *sync.Mutex
	log            *zap.SugaredLogger
	client         *kubernetes.Clientset
	daemonsets     map[string]int
	daemonsetsLock *sync.Mutex
}

// node represent the type for node configuration
type node struct {
	Enforcer      string `json:"enforcer"`
	Runtime       string `json:"runtime"`
	RuntimeSocket string `json:"socket"`
	Arch          string `json:"arch"`
	BTF           string `json:"btf"`
	ApparmorFs    string `json:"apparmorfs"`
	Seccomp       string `json:"seccomp"`
}

// nodeConfigs keeps track for set of node configurations present in the cluster
var nodeConfigs []node

// NewClusterWatcher construct a new clusterwatcher from the provided k8s clientset
func NewClusterWatcher(cfg WatcherConfig, client *kubernetes.Clientset, helmController *helm.Controller) (*ClusterWatcher, error) {
	logger, _ := zap.NewProduction()
	log := logger.With(zap.String("component", "clusterwatcher")).Sugar()
	if informer == nil {
		informer = informers.NewSharedInformerFactory(client, 0)
	}

	operatorDeploymentName = cfg.OperatorDeploymentName
	operatorDeploymentUID = cfg.OperatorDeploymentUID
	operatorWatchedNamespace = cfg.OperatorWatchedNamespace
	snitchPathPrefix = cfg.SnitchPathPrefix
	snitchImage = cfg.SnitchImage
	snitchImagePullPolicy = cfg.SnitchImagePullPolicy
	lsmOrder = cfg.LsmOrder

	if operatorWatchedNamespace == "" {
		log.Fatal("operator is not watching any namespace")
		return nil, fmt.Errorf("operator watched namespace is empty")
	}

	log.Infof("clusterwatcher has configured %+v", cfg)

	return &ClusterWatcher{
		helmController: helmController,
		nodes:          map[string]node{},
		daemonsets:     make(map[string]int),
		log:            log,
		nodesLock:      &sync.Mutex{},
		daemonsetsLock: &sync.Mutex{},
		client:         client,
	}, nil

}

// WatchNodes implements a node informer and deploy snitch on each of the added node
// snitch detects the node configuration and adds that information to node using labels
func (clusterWatcher *ClusterWatcher) WatchNodes() {
	log := clusterWatcher.log
	nodeInformer := informer.Core().V1().Nodes().Informer()
	nodeInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			if nodeObj, ok := obj.(*corev1.Node); ok {
				runtime := nodeObj.Status.NodeInfo.ContainerRuntimeVersion
				runtime = strings.Split(runtime, ":")[0]
				if val, ok := nodeObj.Labels[defaults.OsLabel]; ok && val == "linux" {
					log.Infof("Installing snitch on node %s", nodeObj.Name)
					// install snitch role, rolebinding and sa
					_, err := clusterWatcher.client.RbacV1().ClusterRoles().Create(context.Background(), genSnitchClusterRole(), metav1.CreateOptions{})
					if err != nil && !errors.IsAlreadyExists(err) {
						log.Warnf("cannot create snitch clusterrole error=%s", err.Error())
						return
					}
					_, err = clusterWatcher.client.RbacV1().ClusterRoleBindings().Create(context.Background(), genSnitchClusterRoleBinding(), metav1.CreateOptions{})
					if err != nil && !errors.IsAlreadyExists(err) {
						log.Warnf("cannot create snitch clusterrolebinding error=%s", err.Error())
						return
					}
					_, err = clusterWatcher.client.CoreV1().ServiceAccounts(operatorWatchedNamespace).Create(context.Background(), genSnitchServiceAccount(), metav1.CreateOptions{})
					if err != nil && !errors.IsAlreadyExists(err) {
						log.Warnf("cannot create snitch serviceaccount error=%s", err.Error())
						return
					}
					// deploy snitch job
					_, err = clusterWatcher.client.BatchV1().Jobs(operatorWatchedNamespace).Create(context.Background(), genSnitchDeployment(nodeObj.Name, runtime), metav1.CreateOptions{})
					if err != nil {
						log.Warnf("Cannot run snitch on node %s, error=%s", nodeObj.Name, err.Error())
						return
					}
					log.Infof("Snitch was installed on node %s", nodeObj.Name)
				}
			}
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			if nodeObj, ok := newObj.(*corev1.Node); ok {
				oldRand := ""
				if old, ok := oldObj.(*corev1.Node); ok {
					oldRand = old.Labels[defaults.RandLabel]
				}
				if val, ok := nodeObj.Labels[defaults.OsLabel]; ok && val == "linux" && oldRand != nodeObj.Labels[defaults.RandLabel] {
					newNode := node{}
					if val, ok := nodeObj.Labels[defaults.EnforcerLabel]; ok {
						newNode.Enforcer = val
					}
					if val, ok := nodeObj.Labels[defaults.ArchLabel]; ok {
						newNode.Arch = val
					}
					if val, ok := nodeObj.Labels[defaults.RuntimeLabel]; ok {
						newNode.Runtime = val
					}
					if val, ok := nodeObj.Labels[defaults.SocketLabel]; ok {
						newNode.RuntimeSocket = val
					}
					if val, ok := nodeObj.Labels[defaults.BTFLabel]; ok {
						newNode.BTF = val
					}
					if val, ok := nodeObj.Labels[defaults.ApparmorFsLabel]; ok {
						newNode.ApparmorFs = val
					}
					if val, ok := nodeObj.Labels[defaults.SeccompLabel]; ok {
						newNode.Seccomp = val
					}
					clusterWatcher.nodesLock.Lock()
					nodeModified := false
					if _, ok := clusterWatcher.nodes[nodeObj.Name]; !ok {
						clusterWatcher.nodes[nodeObj.Name] = newNode
						clusterWatcher.log.Infof("Node %s has been added", nodeObj.Name)
					} else {
						if clusterWatcher.nodes[nodeObj.Name].Arch != newNode.Arch ||
							clusterWatcher.nodes[nodeObj.Name].Enforcer != newNode.Enforcer ||
							clusterWatcher.nodes[nodeObj.Name].Runtime != newNode.Runtime ||
							clusterWatcher.nodes[nodeObj.Name].RuntimeSocket != newNode.RuntimeSocket ||
							clusterWatcher.nodes[nodeObj.Name].BTF != newNode.BTF ||
							clusterWatcher.nodes[nodeObj.Name].Seccomp != newNode.Seccomp {
							clusterWatcher.nodes[nodeObj.Name] = newNode
							nodeModified = true
							clusterWatcher.log.Infof("Node %s was updated", nodeObj.Name)
						}
					}
					clusterWatcher.nodesLock.Unlock()
					if nodeModified {
						clusterWatcher.updateDaemonsets(defaults.DeleteAction, newNode)
					}
					clusterWatcher.updateDaemonsets(defaults.AddAction, newNode)
				}
			} else {
				log.Warnf("Cannot convert object to node struct")
				log.Warn(newObj)
			}
		},
		DeleteFunc: func(obj interface{}) {
			if nodeObj, ok := obj.(*corev1.Node); ok {
				clusterWatcher.nodesLock.Lock()
				deletedNode := clusterWatcher.nodes[nodeObj.Name]
				delete(clusterWatcher.nodes, nodeObj.Name)
				clusterWatcher.nodesLock.Unlock()
				clusterWatcher.updateDaemonsets(defaults.DeleteAction, deletedNode)
			}
		},
	})

	nodeInformer.Run(wait.NeverStop)
}

func generateNodeConfigHelmValues(nodes []node) []map[string]interface{} {
	nodeConfigsValues := []map[string]interface{}{}

	for _, n := range nodes {

		nodeConfigsValues = append(nodeConfigsValues, map[string]interface{}{
			"config": convertNodeStructToMapOfStringInterface(n),
		})
	}
	return nodeConfigsValues
}

func convertNodeStructToMapOfStringInterface(node node) map[string]interface{} {
	v := reflect.ValueOf(node)
	result := make(map[string]interface{})
	t := v.Type()
	for i := 0; i < v.NumField(); i++ {
		field := t.Field(i)
		fieldName := field.Tag.Get("json")
		fieldValue := v.Field(i).Interface()
		result[fieldName] = fieldValue
	}
	return result
}

func (clusterWatcher *ClusterWatcher) upgradeRelease() {
	clusterWatcher.helmController.UpdateNodeConfigHelmValues(generateNodeConfigHelmValues(nodeConfigs))
	// release, err := clusterWatcher.helmController.UpgradeRelease(context.TODO())
	// if err != nil {
	// 	clusterWatcher.log.Warnf("error updating release after node config update %s", err.Error())
	// 	return
	// }
	// clusterWatcher.log.Infof("successfully upgraded release %s revision %s", release.Name, release.Version)
	// clusterWatcher.log.Infof("chart info, status=%s chartVersion=%s", release.Info.Status, release.Chart.Metadata.Version)
}

func (clusterWatcher *ClusterWatcher) updateDaemonsets(action string, nodeInstance node) {
	clusterWatcher.log.Info("updating daemonset")
	daemonsetName := strings.Join([]string{
		"kubearmor",
		strings.ReplaceAll(nodeInstance.Enforcer, ".", "-"),
		nodeInstance.Runtime,
		defaults.ShortSHA(nodeInstance.RuntimeSocket),
	}, "-")
	clusterWatcher.daemonsetsLock.Lock()
	if action == defaults.AddAction {
		clusterWatcher.daemonsets[daemonsetName]++
		if !slices.Contains(nodeConfigs, nodeInstance) {
			nodeConfigs = append(nodeConfigs, nodeInstance)
			clusterWatcher.log.Infof("[ADD] nodeConfig: %+v", nodeConfigs)
			// update node config in helm values
			clusterWatcher.upgradeRelease()
		}
	} else if action == defaults.DeleteAction {
		if val, ok := clusterWatcher.daemonsets[daemonsetName]; ok {
			if val < 2 {
				clusterWatcher.daemonsets[daemonsetName] = 0
				nodeConfigs = slices.DeleteFunc(nodeConfigs, func(n node) bool { return reflect.DeepEqual(n, nodeInstance) })
				// update node config in helm values
				clusterWatcher.log.Infof("[DELETE] nodeConfig: %+v", nodeConfigs)
				clusterWatcher.upgradeRelease()
			} else {
				clusterWatcher.daemonsets[daemonsetName]--
			}
		}
	}
	clusterWatcher.log.Info("updated daemonset")
	clusterWatcher.daemonsetsLock.Unlock()
}

// ====================
// snitch k8s resources
// ====================

func genSnitchDeployment(nodename string, runtime string) *batchv1.Job {
	job := batchv1.Job{}
	// job = *addOwnership(&job).(*batchv1.Job)
	ttls := int32(100)
	job.GenerateName = "kubearmor-snitch-"
	var rootUser int64 = 0
	job.Spec = batchv1.JobSpec{
		TTLSecondsAfterFinished: &ttls,
		Template: corev1.PodTemplateSpec{
			ObjectMeta: metav1.ObjectMeta{
				Labels: map[string]string{
					"kubearmor-app": defaults.KubeArmorSnitchRoleName,
				},
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name:  "snitch",
						Image: snitchImage,
						Args: []string{
							"--nodename=$(NODE_NAME)",
							"--pathprefix=" + snitchPathPrefix,
							"--runtime=" + runtime,
							"--lsm=" + lsmOrder,
						},
						Env: []corev1.EnvVar{
							{
								Name: "NODE_NAME",
								ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{
									FieldPath: "spec.nodeName",
								}},
							},
						},
						ImagePullPolicy: corev1.PullPolicy(snitchImagePullPolicy),
						VolumeMounts: []corev1.VolumeMount{

							{
								Name:      "var-path",
								MountPath: fmt.Sprintf("%svar/", snitchPathPrefix),
								ReadOnly:  true,
							},
							{
								Name:      "run-path",
								MountPath: fmt.Sprintf("%srun/", snitchPathPrefix),
								ReadOnly:  true,
							},
							{
								Name:      "sys-path",
								MountPath: fmt.Sprintf("%s/sys/", snitchPathPrefix),
								ReadOnly:  true,
							},
							{
								Name:      "apparmor-path",
								MountPath: fmt.Sprintf("%s/etc/apparmor.d/", snitchPathPrefix),
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
							Privileged: &(defaults.Privileged),
						},
					},
				},
				// For Unknown Reasons hostPID will be true if snitch gets deployed on OpenShift
				// for some reasons github.com/kubearmor/KubeArmor/KubeArmor/utils/bpflsmprobe will
				// not work if hostPID is set false.

				// change for snitch host path
				HostPID:            defaults.HostPID,
				NodeName:           nodename,
				RestartPolicy:      corev1.RestartPolicyOnFailure,
				ServiceAccountName: defaults.KubeArmorSnitchRoleName,
				Volumes: []corev1.Volume{
					{
						Name: "sys-path",
						VolumeSource: corev1.VolumeSource{
							HostPath: &corev1.HostPathVolumeSource{
								Path: "/sys/",
								Type: &defaults.HostPathDirectory,
							},
						},
					},
					{
						Name: "apparmor-path",
						VolumeSource: corev1.VolumeSource{
							HostPath: &corev1.HostPathVolumeSource{
								Path: "/etc/apparmor.d/",
								Type: &defaults.HostPathDirectoryOrCreate,
							},
						},
					},
					{
						Name: "var-path",
						VolumeSource: corev1.VolumeSource{
							HostPath: &corev1.HostPathVolumeSource{
								Path: "/var/",
								Type: &defaults.HostPathDirectory,
							},
						},
					},
					{
						Name: "run-path",
						VolumeSource: corev1.VolumeSource{
							HostPath: &corev1.HostPathVolumeSource{
								Path: "/run/",
								Type: &defaults.HostPathDirectory,
							},
						},
					},
					{
						Name: "seccomp-path",
						VolumeSource: corev1.VolumeSource{
							HostPath: &corev1.HostPathVolumeSource{
								Path: "/var/lib/kubelet/seccomp",
								Type: &defaults.HostPathDirectoryOrCreate,
							},
						},
					},
				},
			},
		},
	}
	return &job
}

func genSnitchClusterRole() *rbacv1.ClusterRole {
	cr := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name:      defaults.KubeArmorSnitchRoleName,
			Namespace: operatorWatchedNamespace,
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
	return addOwnership(cr).(*rbacv1.ClusterRole)
}

func genSnitchClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	crb := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: defaults.KubeArmorSnitchRoleName + "-binding",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      defaults.KubeArmorSnitchRoleName,
				Namespace: operatorWatchedNamespace,
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     defaults.KubeArmorSnitchRoleName,
		},
	}
	return addOwnership(crb).(*rbacv1.ClusterRoleBinding)
}

func genSnitchServiceAccount() *corev1.ServiceAccount {
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      defaults.KubeArmorSnitchRoleName,
			Namespace: operatorWatchedNamespace,
		},
	}
	return addOwnership(sa).(*corev1.ServiceAccount)
}

func addOwnership(obj interface{}) interface{} {
	if operatorDeploymentUID == "" {
		return obj
	}
	OwnerReferences := []metav1.OwnerReference{
		{
			APIVersion: "apps/v1",
			Kind:       "Deployment",
			Name:       operatorDeploymentName,
			UID:        types.UID(operatorDeploymentUID),
		},
	}
	switch resource := obj.(type) {
	case *batchv1.Job:
		resource.OwnerReferences = OwnerReferences
		return resource
	case *corev1.ServiceAccount:
		resource.OwnerReferences = OwnerReferences
		return resource
	case *rbacv1.ClusterRole:
		resource.OwnerReferences = OwnerReferences
		return resource
	case *rbacv1.ClusterRoleBinding:
		resource.OwnerReferences = OwnerReferences
		return resource
	}
	return obj
}
