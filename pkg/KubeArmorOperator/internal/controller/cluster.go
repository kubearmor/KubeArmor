// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package controller

import (
	"context"
	"strconv"
	"strings"
	"sync"
	"time"

	deployments "github.com/kubearmor/KubeArmor/deployments/get"
	opv1 "github.com/kubearmor/KubeArmor/pkg/KubeArmorOperator/api/operator.kubearmor.com/v1"
	opv1client "github.com/kubearmor/KubeArmor/pkg/KubeArmorOperator/client/clientset/versioned"
	opv1Informer "github.com/kubearmor/KubeArmor/pkg/KubeArmorOperator/client/informers/externalversions"
	"github.com/kubearmor/KubeArmor/pkg/KubeArmorOperator/common"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	apiextensionsclientset "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

var informer informers.SharedInformerFactory
var deployment_uuid types.UID
var deployment_name string = "kubearmor-operator"
var PathPrefix string

type ClusterWatcher struct {
	Nodes          []Node
	NodesLock      *sync.Mutex
	Log            *zap.SugaredLogger
	Client         *kubernetes.Clientset
	ExtClient      *apiextensionsclientset.Clientset
	Opv1Client     *opv1client.Clientset
	Daemonsets     map[string]int
	DaemonsetsLock *sync.Mutex
}
type Node struct {
	Name          string
	Enforcer      string
	Runtime       string
	RuntimeSocket string
	Arch          string
	BTF           string
	ApparmorFs    string
	Seccomp       string
}

func NewClusterWatcher(client *kubernetes.Clientset, log *zap.SugaredLogger, extClient *apiextensionsclientset.Clientset, opv1Client *opv1client.Clientset, pathPrefix, deploy_name string) *ClusterWatcher {
	if informer == nil {
		informer = informers.NewSharedInformerFactory(client, 0)
	}
	if deployment_uuid == "" {
		deploy, err := client.AppsV1().Deployments(common.Namespace).Get(context.Background(), deployment_name, v1.GetOptions{})
		if err != nil {
			log.Warnf("Cannot get deployment %s, error=%s", deployment_name, err.Error())
		} else {
			deployment_uuid = deploy.GetUID()
			operatorImage := deploy.Spec.Template.Spec.Containers[0].Image
			common.SnitchImageTag = strings.Split(operatorImage, ":")[1]
		}
	}
	PathPrefix = pathPrefix
	deployment_name = deploy_name
	return &ClusterWatcher{
		Nodes:          []Node{},
		Daemonsets:     make(map[string]int),
		Log:            log,
		NodesLock:      &sync.Mutex{},
		DaemonsetsLock: &sync.Mutex{},
		Client:         client,
		ExtClient:      extClient,
		Opv1Client:     opv1Client,
	}
}

func (clusterWatcher *ClusterWatcher) WatchNodes() {
	log := clusterWatcher.Log
	nodeInformer := informer.Core().V1().Nodes().Informer()
	nodeInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			if node, ok := obj.(*corev1.Node); ok {
				runtime := node.Status.NodeInfo.ContainerRuntimeVersion
				runtime = strings.Split(runtime, ":")[0]
				if val, ok := node.Labels[common.OsLabel]; ok && val == "linux" {
					log.Infof("Installing snitch on node %s", node.Name)
					_, err := clusterWatcher.Client.BatchV1().Jobs(common.Namespace).Create(context.Background(), deploySnitch(node.Name, runtime), v1.CreateOptions{})
					if err != nil {
						log.Errorf("Cannot run snitch on node %s, error=%s", node.Name, err.Error())
						return
					}
					log.Infof("Snitch was installed on node %s", node.Name)
				}
			}
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			if node, ok := newObj.(*corev1.Node); ok {
				oldRand := ""
				if old, ok := oldObj.(*corev1.Node); ok {
					oldRand = old.Labels[common.RandLabel]
				}
				if val, ok := node.Labels[common.OsLabel]; ok && val == "linux" && oldRand != node.Labels[common.RandLabel] {
					newNode := Node{}
					newNode.Name = node.Name
					if val, ok := node.Labels[common.EnforcerLabel]; ok {
						newNode.Enforcer = val
					}
					if val, ok := node.Labels[common.ArchLabel]; ok {
						newNode.Arch = val
					}
					if val, ok := node.Labels[common.RuntimeLabel]; ok {
						newNode.Runtime = val
					}
					if val, ok := node.Labels[common.SocketLabel]; ok {
						newNode.RuntimeSocket = val
					}
					if val, ok := node.Labels[common.BTFLabel]; ok {
						newNode.BTF = val
					}
					if val, ok := node.Labels[common.ApparmorFsLabel]; ok {
						newNode.ApparmorFs = val
					}
					if val, ok := node.Labels[common.SeccompLabel]; ok {
						newNode.Seccomp = val
					}
					clusterWatcher.NodesLock.Lock()
					nbNodes := len(clusterWatcher.Nodes)
					i := 0
					nodeModified := false
					for i < nbNodes && newNode.Name != clusterWatcher.Nodes[i].Name {
						i++
					}
					if i == len(clusterWatcher.Nodes) {
						clusterWatcher.Nodes = append(clusterWatcher.Nodes, newNode)
						clusterWatcher.Log.Infof("Node %s has been added", newNode.Name)
					} else {
						if clusterWatcher.Nodes[i].Arch != newNode.Arch ||
							clusterWatcher.Nodes[i].Enforcer != newNode.Enforcer ||
							clusterWatcher.Nodes[i].Name != newNode.Name ||
							clusterWatcher.Nodes[i].Runtime != newNode.Runtime ||
							clusterWatcher.Nodes[i].RuntimeSocket != newNode.RuntimeSocket ||
							clusterWatcher.Nodes[i].BTF != newNode.BTF ||
							clusterWatcher.Nodes[i].Seccomp != newNode.Seccomp {
							clusterWatcher.Nodes[i] = newNode
							nodeModified = true
							clusterWatcher.Log.Infof("Node %s was updated", node.Name)
						}
					}
					clusterWatcher.NodesLock.Unlock()
					if nodeModified {
						clusterWatcher.UpdateDaemonsets(common.DeleteAction, newNode.Enforcer, newNode.Runtime, newNode.RuntimeSocket, newNode.BTF, newNode.ApparmorFs, newNode.Seccomp)
					}
					clusterWatcher.UpdateDaemonsets(common.AddAction, newNode.Enforcer, newNode.Runtime, newNode.RuntimeSocket, newNode.BTF, newNode.ApparmorFs, newNode.Seccomp)
				}
			} else {
				log.Errorf("Cannot convert object to node struct")
				log.Error(newObj)
			}
		},
		DeleteFunc: func(obj interface{}) {
			if node, ok := obj.(*corev1.Node); ok {
				deletedNode := Node{}
				clusterWatcher.NodesLock.Lock()
				for i, n := range clusterWatcher.Nodes {
					if n.Name == node.Name {
						clusterWatcher.Nodes = append(clusterWatcher.Nodes[:i], clusterWatcher.Nodes[i+1:]...)
						deletedNode = n
						break
					}
				}
				clusterWatcher.NodesLock.Unlock()
				clusterWatcher.UpdateDaemonsets(common.DeleteAction, deletedNode.Enforcer, deletedNode.Runtime, deletedNode.RuntimeSocket, deletedNode.BTF, deletedNode.ApparmorFs, deletedNode.Seccomp)
			}
		},
	})

	nodeInformer.Run(wait.NeverStop)
}

func (clusterWatcher *ClusterWatcher) UpdateDaemonsets(action, enforcer, runtime, socket, btfPresent, apparmorfs, seccompPresent string) {
	clusterWatcher.Log.Info("updating daemonset")
	daemonsetName := strings.Join([]string{
		"kubearmor",
		strings.ReplaceAll(enforcer, ".", "-"),
		runtime,
		common.ShortSHA(socket),
	}, "-")
	newDaemonSet := false
	deleteDaemonSet := false
	clusterWatcher.DaemonsetsLock.Lock()
	if action == common.AddAction {
		clusterWatcher.Daemonsets[daemonsetName]++
		_, err := clusterWatcher.Client.AppsV1().DaemonSets(common.Namespace).Get(context.Background(), daemonsetName, v1.GetOptions{})
		if err != nil {
			newDaemonSet = true
		}
	} else if action == common.DeleteAction {
		if val, ok := clusterWatcher.Daemonsets[daemonsetName]; ok {
			if val < 2 {
				clusterWatcher.Daemonsets[daemonsetName] = 0
				deleteDaemonSet = true
			} else {
				clusterWatcher.Daemonsets[daemonsetName]--
			}
		}
	}
	clusterWatcher.DaemonsetsLock.Unlock()

	if deleteDaemonSet {
		err := clusterWatcher.Client.AppsV1().DaemonSets(common.Namespace).Delete(context.Background(), daemonsetName, v1.DeleteOptions{})
		if err != nil {
			clusterWatcher.Log.Warnf("Cannot delete daemonset %s, error=%s", daemonsetName, err.Error())
		}
	}
	if newDaemonSet {
		daemonset := generateDaemonset(daemonsetName, enforcer, runtime, socket, btfPresent, apparmorfs, seccompPresent)
		_, err := clusterWatcher.Client.AppsV1().DaemonSets(common.Namespace).Create(context.Background(), daemonset, v1.CreateOptions{})
		if err != nil {
			clusterWatcher.Log.Warnf("Cannot Create daemonset %s, error=%s", daemonsetName, err.Error())
		}
	}

}

func (clusterWatcher *ClusterWatcher) WatchConfigCrd() {

	factory := opv1Informer.NewSharedInformerFactoryWithOptions(clusterWatcher.Opv1Client,
		time.Duration(5*time.Second),
		opv1Informer.WithNamespace(common.Namespace))

	informer := factory.Operator().V1().KubeArmorConfigs().Informer()

	if informer == nil {
		clusterWatcher.Log.Warn("Failed to initialize KubeArmorConfig informer")
		return
	}

	var firstRun = true

	informer.AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				configCrdList, err := clusterWatcher.Opv1Client.OperatorV1().KubeArmorConfigs(common.Namespace).List(context.Background(), metav1.ListOptions{})
				if err != nil {
					clusterWatcher.Log.Warn("Failed to list Operator Config CRs")
					return
				}
				for _, cfg := range configCrdList.Items {
					// if there's any crd with Running status
					// mark it as current operating config crd
					if cfg.Status.Phase == common.RUNNING {
						common.OperatorConfigCrd = &cfg
						if firstRun {
							go clusterWatcher.WatchRequiredResources()
							firstRun = false
						}
						break
					}
				}
				if cfg, ok := obj.(*opv1.KubeArmorConfig); ok {
					// if there's no operating crd exist
					if common.OperatorConfigCrd == nil {
						common.OperatorConfigCrd = cfg
						UpdateConfigMapData(&cfg.Spec)
						UpdateImages(&cfg.Spec)
						UpdatedKubearmorRelayEnv(&cfg.Spec)
						UpdatedSeccomp(&cfg.Spec)
						// update status to (Installation) Created
						go clusterWatcher.UpdateCrdStatus(cfg.Name, common.CREATED, common.CREATED_MSG)
						go clusterWatcher.WatchRequiredResources()
						firstRun = false
					}
					// if it's not the operating crd
					// update this crd status as Error and return
					if cfg.Name != common.OperatorConfigCrd.Name {
						go clusterWatcher.UpdateCrdStatus(cfg.Name, common.ERROR, common.MULTIPLE_CRD_ERR_MSG)
						return
					}

				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				if cfg, ok := newObj.(*opv1.KubeArmorConfig); ok {
					// update configmap only if it's operating crd
					if common.OperatorConfigCrd != nil && cfg.Name == common.OperatorConfigCrd.Name {
						configChanged := UpdateConfigMapData(&cfg.Spec)
						imageUpdated := UpdateImages(&cfg.Spec)
						relayEnvUpdated := UpdatedKubearmorRelayEnv(&cfg.Spec)
						seccompEnabledUpdated := UpdatedSeccomp(&cfg.Spec)
						// return if only status has been updated
						if !configChanged && cfg.Status != oldObj.(*opv1.KubeArmorConfig).Status && len(imageUpdated) < 1 {
							return
						}
						if len(imageUpdated) > 0 {
							clusterWatcher.UpdateKubeArmorImages(imageUpdated)
						}
						if configChanged {
							// update status to Updating
							go clusterWatcher.UpdateCrdStatus(cfg.Name, common.UPDATING, common.UPDATING_MSG)
							clusterWatcher.UpdateKubeArmorConfigMap(cfg)
						}
						if relayEnvUpdated {
							// update status to Updating
							go clusterWatcher.UpdateCrdStatus(cfg.Name, common.UPDATING, common.UPDATING_MSG)
							clusterWatcher.UpdateKubearmorRelayEnv(cfg)
						}
						if seccompEnabledUpdated {
							go clusterWatcher.UpdateCrdStatus(cfg.Name, common.UPDATING, common.UPDATING_MSG)
							clusterWatcher.UpdateKubearmorSeccomp(cfg)
						}
					}
				}
			},
			DeleteFunc: func(obj interface{}) {
				if cfg, ok := obj.(*opv1.KubeArmorConfig); ok {
					if common.OperatorConfigCrd != nil && cfg.Name == common.OperatorConfigCrd.Name {
						common.OperatorConfigCrd = nil
					}
				}
			},
		},
	)

	go informer.Run(wait.NeverStop)

	if ok := cache.WaitForCacheSync(wait.NeverStop, informer.HasSynced); !ok {
		clusterWatcher.Log.Warn("Failed to wait for cache sync")
	}
}

func (clusterWatcher *ClusterWatcher) UpdateKubeArmorImages(images []string) error {
	var res error
	for _, img := range images {
		switch img {
		case "kubearmor", "init":
			dsList, err := clusterWatcher.Client.AppsV1().DaemonSets(common.Namespace).List(context.Background(), v1.ListOptions{
				LabelSelector: "kubearmor-app=kubearmor",
			})
			if err != nil {
				clusterWatcher.Log.Warnf("Cannot list KubeArmor daemonset(s) error=%s", err.Error())
				res = err
			} else {
				for _, ds := range dsList.Items {
					ds.Spec.Template.Spec.Containers[0].Image = common.GetApplicationImage(common.KubeArmorName)
					ds.Spec.Template.Spec.Containers[0].ImagePullPolicy = corev1.PullPolicy(common.KubeArmorInitImagePullPolicy)
					ds.Spec.Template.Spec.InitContainers[0].Image = common.GetApplicationImage(common.KubeArmorInitName)
					ds.Spec.Template.Spec.InitContainers[0].ImagePullPolicy = corev1.PullPolicy(common.KubeArmorInitImagePullPolicy)
					_, err = clusterWatcher.Client.AppsV1().DaemonSets(common.Namespace).Update(context.Background(), &ds, v1.UpdateOptions{})
					if err != nil {
						clusterWatcher.Log.Warnf("Cannot update daemonset=%s error=%s", ds.Name, err.Error())
						res = err
					} else {
						clusterWatcher.Log.Infof("Updated daemonset=%s", ds.Name)
					}
				}
			}
		case "relay":
			relay, err := clusterWatcher.Client.AppsV1().Deployments(common.Namespace).Get(context.Background(), deployments.RelayDeploymentName, v1.GetOptions{})
			if err != nil {
				clusterWatcher.Log.Warnf("Cannot get deployment=%s error=%s", deployments.RelayDeploymentName, err.Error())
				res = err
			} else {
				relay.Spec.Template.Spec.Containers[0].Image = common.GetApplicationImage(common.KubeArmorRelayName)
				relay.Spec.Template.Spec.Containers[0].ImagePullPolicy = corev1.PullPolicy(common.KubeArmorRelayImagePullPolicy)
				_, err = clusterWatcher.Client.AppsV1().Deployments(common.Namespace).Update(context.Background(), relay, v1.UpdateOptions{})
				if err != nil {
					clusterWatcher.Log.Warnf("Cannot update deployment=%s error=%s", deployments.RelayDeploymentName, err.Error())
					res = err
				} else {
					clusterWatcher.Log.Infof("Updated Deployment=%s with image=%s", deployments.RelayDeploymentName, common.KubeArmorRelayImage)
				}
			}

		case "controller", "rbac":
			controller, err := clusterWatcher.Client.AppsV1().Deployments(common.Namespace).Get(context.Background(), deployments.KubeArmorControllerDeploymentName, v1.GetOptions{})
			if err != nil {
				clusterWatcher.Log.Warnf("Cannot get deployment=%s error=%s", deployments.KubeArmorControllerDeploymentName, err.Error())
				res = err
			} else {
				containers := &controller.Spec.Template.Spec.Containers
				for i, container := range *containers {
					if container.Name == "manager" {
						(*containers)[i].Image = common.GetApplicationImage(common.KubeArmorControllerName)
						(*containers)[i].ImagePullPolicy = corev1.PullPolicy(common.KubeArmorControllerImagePullPolicy)
					} else {
						(*containers)[i].Image = common.GetApplicationImage(common.KubeRbacProxyName)
					}
				}
				_, err = clusterWatcher.Client.AppsV1().Deployments(common.Namespace).Update(context.Background(), controller, v1.UpdateOptions{})
				if err != nil {
					clusterWatcher.Log.Warnf("Cannot update deployment=%s error=%s", deployments.KubeArmorControllerDeploymentName, err.Error())
					res = err
				} else {
					clusterWatcher.Log.Infof("Updated Deployment=%s", deployments.KubeArmorControllerDeploymentName)
				}
			}
		}
	}

	return res
}

func (clusterWatcher *ClusterWatcher) UpdateKubearmorRelayEnv(cfg *opv1.KubeArmorConfig) error {
	var res error
	relay, err := clusterWatcher.Client.AppsV1().Deployments(common.Namespace).Get(context.Background(), deployments.RelayDeploymentName, v1.GetOptions{})
	if err != nil {
		clusterWatcher.Log.Warnf("Cannot get deployment=%s error=%s", deployments.RelayDeploymentName, err.Error())
		res = err
	} else {
		relay.Spec.Template.Spec.Containers[0].Env = []corev1.EnvVar{
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
		}
		_, err = clusterWatcher.Client.AppsV1().Deployments(common.Namespace).Update(context.Background(), relay, v1.UpdateOptions{})
		if err != nil {
			clusterWatcher.Log.Warnf("Cannot update deployment=%s error=%s", deployments.RelayDeploymentName, err.Error())
			res = err
		} else {
			clusterWatcher.Log.Infof("Updated Deployment=%s with env=%s", deployments.RelayDeploymentName, common.KubearmorRelayEnvMap)
		}
	}
	return res
}

func (clusterWatcher *ClusterWatcher) UpdateKubearmorSeccomp(cfg *opv1.KubeArmorConfig) error {
	var res error
	dsList, err := clusterWatcher.Client.AppsV1().DaemonSets(common.Namespace).List(context.Background(), v1.ListOptions{
		LabelSelector: "kubearmor-app=kubearmor",
	})
	if err != nil {
		clusterWatcher.Log.Warnf("Cannot list KubeArmor daemonset(s) error=%s", err.Error())
		res = err
	} else {
		for _, ds := range dsList.Items {
			if ds.Spec.Template.Labels[common.SeccompLabel] == "yes" {
				if cfg.Spec.SeccompEnabled && ds.Spec.Template.Spec.Containers[0].SecurityContext.SeccompProfile == nil {
					ds.Spec.Template.Spec.Containers[0].SecurityContext.SeccompProfile = &corev1.SeccompProfile{
						Type:             corev1.SeccompProfileTypeLocalhost,
						LocalhostProfile: &common.SeccompProfile,
					}
					ds.Spec.Template.Spec.InitContainers[0].SecurityContext.SeccompProfile = &corev1.SeccompProfile{
						Type:             corev1.SeccompProfileTypeLocalhost,
						LocalhostProfile: &common.SeccompInitProfile,
					}
				} else if !cfg.Spec.SeccompEnabled && ds.Spec.Template.Spec.Containers[0].SecurityContext.SeccompProfile != nil {
					ds.Spec.Template.Spec.Containers[0].SecurityContext.SeccompProfile = nil
					ds.Spec.Template.Spec.InitContainers[0].SecurityContext.SeccompProfile = nil
				}

				_, err = clusterWatcher.Client.AppsV1().DaemonSets(common.Namespace).Update(context.Background(), &ds, v1.UpdateOptions{})
				if err != nil {
					clusterWatcher.Log.Warnf("Cannot update daemonset=%s error=%s", ds.Name, err.Error())
					res = err
				} else {
					clusterWatcher.Log.Infof("Updated daemonset=%s", ds.Name)
				}
			}
		}
	}

	return res
}

func UpdateIfDefinedAndUpdated(common *string, in string) bool {
	if in != "" && in != *common {
		*common = in
		return true
	}
	return false
}

func UpdateImages(config *opv1.KubeArmorConfigSpec) []string {
	updatedImages := []string{}
	// if kubearmor image or imagePullPolicy got updated
	if UpdateIfDefinedAndUpdated(&common.KubeArmorImage, config.KubeArmorImage.Image) ||
		UpdateIfDefinedAndUpdated(&common.KubeArmorImagePullPolicy, config.KubeArmorImage.ImagePullPolicy) {
		updatedImages = append(updatedImages, "kubearmor")
	}
	// if kubearmor-init image or imagePullPolicy got updated
	if UpdateIfDefinedAndUpdated(&common.KubeArmorInitImage, config.KubeArmorInitImage.Image) ||
		UpdateIfDefinedAndUpdated(&common.KubeArmorInitImagePullPolicy, config.KubeArmorInitImage.ImagePullPolicy) {
		updatedImages = append(updatedImages, "init")
	}
	// kubearmor-relay image or imagePullPolicy got updated
	if UpdateIfDefinedAndUpdated(&common.KubeArmorRelayImage, config.KubeArmorRelayImage.Image) ||
		UpdateIfDefinedAndUpdated(&common.KubeArmorRelayImagePullPolicy, config.KubeArmorRelayImage.ImagePullPolicy) {
		updatedImages = append(updatedImages, "relay")
	}
	// if kubearmor-controller image or imagePullPolicy got updated
	if UpdateIfDefinedAndUpdated(&common.KubeArmorControllerImage, config.KubeArmorControllerImage.Image) ||
		UpdateIfDefinedAndUpdated(&common.KubeArmorControllerImagePullPolicy, config.KubeArmorControllerImage.ImagePullPolicy) {
		updatedImages = append(updatedImages, "controller")
	}
	// if kube-rbac-proxy image or imagePullPolicy got updated
	if UpdateIfDefinedAndUpdated(&common.KubeRbacProxyImage, config.KubeRbacProxyImage.Image) ||
		UpdateIfDefinedAndUpdated(&common.KubeRbacProxyImagePullPolicy, config.KubeRbacProxyImage.ImagePullPolicy) {
		updatedImages = append(updatedImages, "rbac")
	}
	return updatedImages
}

func (clusterWatcher *ClusterWatcher) UpdateCrdStatus(cfg, phase, message string) {
	err := wait.ExponentialBackoff(wait.Backoff{Steps: 5, Duration: 500 * time.Millisecond}, func() (bool, error) {
		configCrd, err := clusterWatcher.Opv1Client.OperatorV1().KubeArmorConfigs(common.Namespace).Get(context.Background(), cfg, metav1.GetOptions{})
		if err != nil {
			// retry the update
			return false, nil
		}
		newStatus := opv1.KubeArmorConfigStatus{
			Phase:   phase,
			Message: message,
		}
		// update status only if there's any change
		if configCrd.Status != newStatus {
			configCrd.Status = newStatus
			_, err = clusterWatcher.Opv1Client.OperatorV1().KubeArmorConfigs(common.Namespace).UpdateStatus(context.Background(), configCrd, metav1.UpdateOptions{})
			if err != nil {
				// retry the update
				return false, nil
			}
		}
		return true, nil
	})
	if err != nil {
		clusterWatcher.Log.Errorf("Error updating the ConfigCR status %s", err)
		return
	}
	clusterWatcher.Log.Info("Config CR Status Updated Successfully")
}

func (clusterWatcher *ClusterWatcher) UpdateKubeArmorConfigMap(cfg *opv1.KubeArmorConfig) {
	err := wait.ExponentialBackoff(wait.Backoff{Steps: 5, Duration: 500 * time.Millisecond}, func() (bool, error) {
		cm, err := clusterWatcher.Client.CoreV1().ConfigMaps(common.Namespace).Get(context.Background(), deployments.KubeArmorConfigMapName, metav1.GetOptions{})
		if err != nil {
			if isNotfound(err) {
				return true, nil
			}
			// retry the update
			return false, nil
		}
		cm.Data = common.ConfigMapData
		_, err = clusterWatcher.Client.CoreV1().ConfigMaps(common.Namespace).Update(context.Background(), cm, metav1.UpdateOptions{})
		if err != nil {
			// retry the update
			return false, nil
		}
		return true, nil
	})

	if err != nil {
		clusterWatcher.Log.Errorf("Error updating the KubeArmor Configmap %s", err)
		go clusterWatcher.UpdateCrdStatus(cfg.Name, common.ERROR, common.UPDATION_FAILED_ERR_MSG)
		return
	}
	go clusterWatcher.UpdateCrdStatus(cfg.Name, common.RUNNING, common.RUNNING_MSG)
	clusterWatcher.Log.Info("KubeArmor Config Updated Successfully")
}

func UpdateConfigMapData(config *opv1.KubeArmorConfigSpec) bool {
	updated := false
	if config.DefaultFilePosture != "" {
		if common.ConfigMapData[common.ConfigDefaultFilePosture] != string(config.DefaultFilePosture) {
			common.ConfigMapData[common.ConfigDefaultFilePosture] = string(config.DefaultFilePosture)
			updated = true
		}
	}
	if config.DefaultCapabilitiesPosture != "" {
		if common.ConfigMapData[common.ConfigDefaultCapabilitiesPosture] != string(config.DefaultCapabilitiesPosture) {
			common.ConfigMapData[common.ConfigDefaultCapabilitiesPosture] = string(config.DefaultCapabilitiesPosture)
			updated = true
		}
	}
	if config.DefaultNetworkPosture != "" {
		if common.ConfigMapData[common.ConfigDefaultNetworkPosture] != string(config.DefaultNetworkPosture) {
			common.ConfigMapData[common.ConfigDefaultNetworkPosture] = string(config.DefaultNetworkPosture)
			updated = true
		}
	}
	if config.DefaultVisibility != "" {
		if common.ConfigMapData[common.ConfigVisibility] != config.DefaultVisibility {
			common.ConfigMapData[common.ConfigVisibility] = config.DefaultVisibility
			updated = true
		}
	}

	return updated
}

func UpdatedKubearmorRelayEnv(config *opv1.KubeArmorConfigSpec) bool {
	updated := false
	stringEnableStdOutLogs := strconv.FormatBool(config.EnableStdOutLogs)
	if stringEnableStdOutLogs != "" {
		if common.KubearmorRelayEnvMap[common.EnableStdOutLogs] != stringEnableStdOutLogs {
			common.KubearmorRelayEnvMap[common.EnableStdOutLogs] = stringEnableStdOutLogs
			updated = true
		}
	}

	stringEnableStdOutAlerts := strconv.FormatBool(config.EnableStdOutAlerts)
	if stringEnableStdOutAlerts != "" {
		if common.KubearmorRelayEnvMap[common.EnableStdOutAlerts] != stringEnableStdOutAlerts {
			common.KubearmorRelayEnvMap[common.EnableStdOutAlerts] = stringEnableStdOutAlerts
			updated = true
		}
	}

	stringEnableStdOutMsgs := strconv.FormatBool(config.EnableStdOutMsgs)
	if stringEnableStdOutMsgs != "" {
		if common.KubearmorRelayEnvMap[common.EnableStdOutMsgs] != stringEnableStdOutMsgs {
			common.KubearmorRelayEnvMap[common.EnableStdOutMsgs] = stringEnableStdOutMsgs
			updated = true
		}
	}
	return updated
}

func UpdatedSeccomp(config *opv1.KubeArmorConfigSpec) bool {
	updated := false
	stringSeccompEnabled := strconv.FormatBool(config.SeccompEnabled)
	if stringSeccompEnabled != "" {
		if common.ConfigDefaultSeccompEnabled != stringSeccompEnabled {
			common.ConfigDefaultSeccompEnabled = stringSeccompEnabled
			updated = true
		}
	}
	return updated
}
