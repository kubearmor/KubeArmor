// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package controller

import (
	"bytes"
	"context"
	"fmt"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	certutil "github.com/kubearmor/KubeArmor/KubeArmor/cert"
	deployments "github.com/kubearmor/KubeArmor/deployments/get"
	secv1 "github.com/kubearmor/KubeArmor/pkg/KubeArmorController/api/security.kubearmor.com/v1"
	secv1client "github.com/kubearmor/KubeArmor/pkg/KubeArmorController/client/clientset/versioned"
	opv1 "github.com/kubearmor/KubeArmor/pkg/KubeArmorOperator/api/operator.kubearmor.com/v1"
	"github.com/kubearmor/KubeArmor/pkg/KubeArmorOperator/cert"
	opv1client "github.com/kubearmor/KubeArmor/pkg/KubeArmorOperator/client/clientset/versioned"
	"github.com/kubearmor/KubeArmor/pkg/KubeArmorOperator/client/clientset/versioned/scheme"
	opv1Informer "github.com/kubearmor/KubeArmor/pkg/KubeArmorOperator/client/informers/externalversions"
	"github.com/kubearmor/KubeArmor/pkg/KubeArmorOperator/common"
	"github.com/kubearmor/KubeArmor/pkg/KubeArmorOperator/recommend"
	"github.com/kubearmor/KubeArmor/pkg/KubeArmorOperator/utils"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	apiextensionsclientset "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	metav1errors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/kubectl/pkg/util/slice"
)

var informer informers.SharedInformerFactory
var deployment_uuid types.UID
var deployment_name string = "kubearmor-operator"
var PathPrefix string
var initDeploy, annotateResource, annotateExisting bool
var ProviderHostname, ProviderEndpoint string
var ImagePullSecrets []corev1.LocalObjectReference

type ClusterWatcher struct {
	Nodes          []Node
	NodesLock      *sync.Mutex
	Log            *zap.SugaredLogger
	Client         *kubernetes.Clientset
	ExtClient      *apiextensionsclientset.Clientset
	Opv1Client     *opv1client.Clientset
	Secv1Client    *secv1client.Clientset
	Daemonsets     map[string]int
	DaemonsetsLock *sync.Mutex
}
type Node struct {
	Name             string
	Enforcer         string
	Runtime          string
	RuntimeSocket    string
	NRIRuntimeSocket string
	Arch             string
	BTF              string
	ApparmorFs       string
	Seccomp          string
	OCIHooks         string
}

func NewClusterWatcher(client *kubernetes.Clientset, log *zap.SugaredLogger, extClient *apiextensionsclientset.Clientset, opv1Client *opv1client.Clientset, secv1Client *secv1client.Clientset, pathPrefix, deploy_name, providerHostname, providerEndpoint string, initdeploy, annotateresource, annotateexisting bool, imagePullSecrets []string) *ClusterWatcher {
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
	initDeploy = initdeploy
	annotateResource = annotateresource
	annotateExisting = annotateexisting
	ProviderHostname = providerHostname
	ProviderEndpoint = providerEndpoint

	// add image pull secrets
	ImagePullSecrets = utils.SanitizePullSecrets(imagePullSecrets)

	return &ClusterWatcher{
		Nodes:          []Node{},
		Daemonsets:     make(map[string]int),
		Log:            log,
		NodesLock:      &sync.Mutex{},
		DaemonsetsLock: &sync.Mutex{},
		Client:         client,
		ExtClient:      extClient,
		Opv1Client:     opv1Client,
		Secv1Client:    secv1Client,
	}
}

func extractPathFromMessage(message string) (string, bool) {
	// find mount path between quotes after "mkdir"
	// Message: failed to mkdir \"/etc/apparmor.d/\": mkdir /etc/apparmor.d/: read-only file system
	re := regexp.MustCompile(`mkdir\s+\"([^\"]+)\"`)
	matches := re.FindStringSubmatch(message)

	if len(matches) > 1 {
		return matches[1], true
	}
	return "", false
}

func (clusterWatcher *ClusterWatcher) checkJobStatus(job, runtime, nodename string) {
	defer func() {
		clusterWatcher.Log.Infof("checkJobStatus completed for job: %s", job)
	}()

	for {
		select {
		case <-time.After(5 * time.Minute):
			clusterWatcher.Log.Infof("watcher exit after timeout for job: %s", job)
			return
		default:
			clusterWatcher.Log.Infof("watching status for job: %s", job)

			j, err := clusterWatcher.Client.BatchV1().Jobs(common.Namespace).Get(context.TODO(), job, v1.GetOptions{})
			if err != nil {
				clusterWatcher.Log.Warnf("cannot get job: %s err: %s", job, err)
				return
			}

			if j.Status.Succeeded > 0 {
				return
			}

			podsList, err := clusterWatcher.Client.CoreV1().Pods(common.Namespace).List(context.TODO(), v1.ListOptions{
				LabelSelector: fmt.Sprintf("job-name=%s", job),
			})

			if err != nil {
				clusterWatcher.Log.Warnf("Cannot get job pod: %s err: %s", job, err)
				return
			}

			for _, pod := range podsList.Items {
				mountFailure := false
				failedMount := ""
				events, err := clusterWatcher.Client.CoreV1().Events(common.Namespace).List(context.TODO(), v1.ListOptions{
					FieldSelector: fmt.Sprintf("involvedObject.name=%s", pod.Name),
				})
				if err != nil {
					clusterWatcher.Log.Warnf("cannot get pod events for pod: %s err: %s", pod.Name, err)
					return
				}

				for _, event := range events.Items {
					if event.Type == "Warning" && (event.Reason == "FailedMount" ||
						event.Reason == "FailedAttachVolume" ||
						event.Reason == "VolumeMountsFailed") {
						clusterWatcher.Log.Infof("Got Failed Event for job pod: %v", event.Message)
						mountFailure = true
						failedMount, _ = utils.ExtractVolumeFromMessage(event.Message)
						clusterWatcher.Log.Infof("FailedMount: %s", failedMount)
						break
					}

					if event.Type == "Warning" && event.Reason == "Failed" && strings.Contains(event.Message, "mkdir") {
						clusterWatcher.Log.Infof("Got Failed Event for job pod: %v", event.Message)
						if path, readOnly := utils.ExtractPathFromMessage(event.Message); readOnly {
							failedMount = path
							mountFailure = true
							clusterWatcher.Log.Infof("ReadOnly FS: %s", failedMount)
							break
						}
					}
				}

				if mountFailure {
					propogatePodDeletion := v1.DeletePropagationBackground
					err := clusterWatcher.Client.BatchV1().Jobs(common.Namespace).Delete(context.TODO(), job, v1.DeleteOptions{
						PropagationPolicy: &propogatePodDeletion,
					})
					if err != nil {
						clusterWatcher.Log.Warnf("Cannot delete job: %s, err=%s", job, err)
						return
					}

					newJob := deploySnitch(nodename, runtime)
					newJob.Spec.Template.Spec.Volumes = j.Spec.Template.Spec.Volumes
					newJob.Spec.Template.Spec.Containers[0].VolumeMounts = j.Spec.Template.Spec.Containers[0].VolumeMounts

					volumeToDelete := ""
					for _, vol := range newJob.Spec.Template.Spec.Volumes {
						if vol.HostPath.Path == failedMount || vol.Name == failedMount {
							volumeToDelete = vol.Name
							break
						}
					}

					newJob.Spec.Template.Spec.Volumes = slices.DeleteFunc(newJob.Spec.Template.Spec.Volumes, func(vol corev1.Volume) bool {
						if vol.Name == volumeToDelete {
							return true
						}
						return false
					})

					newJob.Spec.Template.Spec.Containers[0].VolumeMounts = slices.DeleteFunc(newJob.Spec.Template.Spec.Containers[0].VolumeMounts, func(volMount corev1.VolumeMount) bool {
						if volMount.Name == volumeToDelete {
							return true
						}
						return false
					})

					newJ, err := clusterWatcher.Client.BatchV1().Jobs(common.Namespace).Create(context.TODO(), newJob, v1.CreateOptions{})
					if err != nil {
						clusterWatcher.Log.Warnf("Cannot create job: %s, error=%s", newJob.Name, err)
						return
					}
					job = newJ.Name
					break
				}
			}
		}
	}
}

func (clusterWatcher *ClusterWatcher) WatchNodes() {
	log := clusterWatcher.Log
	nodeInformer := informer.Core().V1().Nodes().Informer()
	nodeInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj any) {
			if node, ok := obj.(*corev1.Node); ok {
				runtime := node.Status.NodeInfo.ContainerRuntimeVersion
				runtime = strings.Split(runtime, ":")[0]
				if val, ok := node.Labels[common.OsLabel]; ok && val == "linux" {
					log.Infof("Installing snitch on node %s", node.Name)
					snitchJob, err := clusterWatcher.Client.BatchV1().Jobs(common.Namespace).Create(context.Background(), deploySnitch(node.Name, runtime), v1.CreateOptions{})
					if err != nil {
						log.Errorf("Cannot run snitch on node %s, error=%s", node.Name, err.Error())
						return
					}
					log.Infof("Snitch was installed on node %s", node.Name)
					go clusterWatcher.checkJobStatus(snitchJob.Name, runtime, node.Name)
				}
			}
		},
		UpdateFunc: func(oldObj, newObj any) {

			if node, ok := newObj.(*corev1.Node); ok {
				oldRand := ""
				if old, ok := oldObj.(*corev1.Node); ok {
					oldRand = old.Labels[common.RandLabel]

					nodeRestart := utils.CheckNodeRestart(node, old)
					if nodeRestart {
						runtime := node.Status.NodeInfo.ContainerRuntimeVersion
						runtime = strings.Split(runtime, ":")[0]
						clusterWatcher.Log.Infof("Node might have been restarted, redeploying snitch ")
						if val, ok := node.Labels[common.OsLabel]; ok && val == "linux" {
							log.Infof("Installing snitch on node %s", node.Name)
							snitchJob, err := clusterWatcher.Client.BatchV1().Jobs(common.Namespace).Create(context.Background(), deploySnitch(node.Name, runtime), v1.CreateOptions{})
							if err != nil {
								log.Errorf("Cannot run snitch on node %s, error=%s", node.Name, err.Error())
								return
							}
							log.Infof("Snitch was installed on node %s", node.Name)
							go clusterWatcher.checkJobStatus(snitchJob.Name, runtime, node.Name)
						}
					}
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
					if val, ok := node.Labels[common.NRISocketLabel]; ok {
						newNode.NRIRuntimeSocket = val
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
					if val, ok := node.Labels[common.OCIHooksLabel]; ok {
						newNode.OCIHooks = val
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
							clusterWatcher.Nodes[i].NRIRuntimeSocket != newNode.NRIRuntimeSocket ||
							clusterWatcher.Nodes[i].BTF != newNode.BTF ||
							clusterWatcher.Nodes[i].Seccomp != newNode.Seccomp ||
							clusterWatcher.Nodes[i].OCIHooks != newNode.OCIHooks {
							clusterWatcher.Nodes[i] = newNode
							nodeModified = true
							clusterWatcher.Log.Infof("Node %s was updated", node.Name)
						}
					}
					clusterWatcher.NodesLock.Unlock()
					if nodeModified {
						clusterWatcher.UpdateDaemonsets(common.DeleteAction, newNode.Enforcer, newNode.Runtime, newNode.RuntimeSocket, newNode.NRIRuntimeSocket, newNode.BTF, newNode.ApparmorFs, newNode.Seccomp, newNode.OCIHooks)
					}
					clusterWatcher.UpdateDaemonsets(common.AddAction, newNode.Enforcer, newNode.Runtime, newNode.RuntimeSocket, newNode.NRIRuntimeSocket, newNode.BTF, newNode.ApparmorFs, newNode.Seccomp, newNode.OCIHooks)
				}
			} else {
				log.Errorf("Cannot convert object to node struct")
				log.Error(newObj)
			}
		},
		DeleteFunc: func(obj any) {
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
				clusterWatcher.UpdateDaemonsets(common.DeleteAction, deletedNode.Enforcer, deletedNode.Runtime, deletedNode.RuntimeSocket, deletedNode.NRIRuntimeSocket, deletedNode.BTF, deletedNode.ApparmorFs, deletedNode.Seccomp, deletedNode.OCIHooks)
			}
		},
	})

	nodeInformer.Run(wait.NeverStop)
}

func (clusterWatcher *ClusterWatcher) UpdateDaemonsets(action, enforcer, runtime, socket, nriSocket, btfPresent, apparmorfs, seccompPresent, ociHooks string) {
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
		daemonset := generateDaemonset(daemonsetName, enforcer, runtime, socket, nriSocket, btfPresent, apparmorfs, seccompPresent, initDeploy, ociHooks)
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
			AddFunc: func(obj any) {
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
						clusterWatcher.Log.Info("kubearmorconfig CR created")
						UpdateTlsData(&cfg.Spec)
						UpdateConfigMapData(&cfg.Spec)
						UpdateImages(&cfg.Spec)
						UpdatedKubearmorRelayEnv(&cfg.Spec)
						UpdatedSeccomp(&cfg.Spec)
						UpdateRecommendedPolicyConfig(&cfg.Spec)
						utils.UpdateControllerPort(&cfg.Spec)
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
			UpdateFunc: func(oldObj, newObj any) {
				if cfg, ok := newObj.(*opv1.KubeArmorConfig); ok {
					// update configmap only if it's operating crd
					if common.OperatorConfigCrd != nil && cfg.Name == common.OperatorConfigCrd.Name {
						configChanged := UpdateConfigMapData(&cfg.Spec)
						imageUpdated := UpdateImages(&cfg.Spec)
						controllerPortUpdated := utils.UpdateControllerPort(&cfg.Spec)
						relayEnvUpdated := UpdatedKubearmorRelayEnv(&cfg.Spec)
						seccompEnabledUpdated := UpdatedSeccomp(&cfg.Spec)
						tlsUpdated := UpdateTlsData(&cfg.Spec)
						UpdateRecommendedPolicyConfig(&cfg.Spec)

						// return if only status has been updated
						if !tlsUpdated && !relayEnvUpdated && !configChanged && cfg.Status != oldObj.(*opv1.KubeArmorConfig).Status && len(imageUpdated) < 1 && !controllerPortUpdated {
							return
						}
						if tlsUpdated {
							// update tls configuration
							clusterWatcher.Log.Infof("config tls data updated: %v", cfg.Spec.Tls.Enable)
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
						if controllerPortUpdated {
							clusterWatcher.UpdateKubeArmorImages([]string{"controller"})
							clusterWatcher.UpdateWebhookSvcPort(cfg.Spec.ControllerPort)
						}
					}
				}
			},
			DeleteFunc: func(obj any) {
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
					ds.Spec.Template.Spec.Containers[0].ImagePullPolicy = corev1.PullPolicy(common.KubeArmorImagePullPolicy)
					ds.Spec.Template.Spec.Containers[0].Args = common.KubeArmorArgs
					ds.Spec.Template.Spec.ImagePullSecrets = common.KubeArmorImagePullSecrets
					if len(ds.Spec.Template.Spec.ImagePullSecrets) < 1 {
						utils.UpdateImagePullSecretFromGlobal(common.GlobalImagePullSecrets, &ds.Spec.Template.Spec.ImagePullSecrets)
					}
					if len(ds.Spec.Template.Spec.ImagePullSecrets) == 0 && len(ImagePullSecrets) > 0 {
						UpdateImagePullSecretsIfDefinedAndUpdated(&ds.Spec.Template.Spec.ImagePullSecrets, ImagePullSecrets)
					}
					ds.Spec.Template.Spec.Tolerations = common.KubeArmorTolerations
					if len(ds.Spec.Template.Spec.Tolerations) < 1 {
						utils.UpdateTolerationFromGlobal(common.GlobalTolerations, &ds.Spec.Template.Spec.Tolerations)
					}

					// update with globalNodeSelector
					AddOrUpdateNodeSelector(ds.Spec.Template.Spec.NodeSelector, common.GlobalNodeSelectors)
					// add/override with kubearmor specific nodeSelector
					if len(common.KubeArmorNodeSelector) > 0 {
						defer RemoveDeletedEntriesForNodeSelector(common.KubeArmorNodeSelector)
						AddOrUpdateNodeSelector(ds.Spec.Template.Spec.NodeSelector, common.KubeArmorNodeSelector)
					}

					// update with global env
					AddOrUpdateEnv(&ds.Spec.Template.Spec.Containers[0].Env, common.GlobalEnv)
					// add/override with kubearmor specific env
					if len(common.KubeArmorEnv) > 0 {
						defer RemoveDeletedEntriesForEnv(&common.KubeArmorEnv)
						AddOrUpdateEnv(&ds.Spec.Template.Spec.Containers[0].Env, common.KubeArmorEnv)
					}

					if len(ds.Spec.Template.Spec.InitContainers) != 0 {
						ds.Spec.Template.Spec.InitContainers[0].Image = common.GetApplicationImage(common.KubeArmorInitName)
						ds.Spec.Template.Spec.InitContainers[0].ImagePullPolicy = corev1.PullPolicy(common.KubeArmorInitImagePullPolicy)
						ds.Spec.Template.Spec.InitContainers[0].Args = common.KubeArmorInitArgs
						ds.Spec.Template.Spec.ImagePullSecrets = append(ds.Spec.Template.Spec.ImagePullSecrets, common.KubeArmorInitImagePullSecrets...)
						ds.Spec.Template.Spec.Tolerations = append(ds.Spec.Template.Spec.Tolerations, common.KubeArmorInitTolerations...)
					}

					// update with global env
					AddOrUpdateEnv(&ds.Spec.Template.Spec.InitContainers[0].Env, common.GlobalEnv)
					// add/override with kubearmor-init specific env
					if len(common.KubeArmorInitEnv) > 0 {
						defer RemoveDeletedEntriesForEnv(&common.KubeArmorInitEnv)
						AddOrUpdateEnv(&ds.Spec.Template.Spec.InitContainers[0].Env, common.KubeArmorInitEnv)
					}

					NRIVolume, NRIVolumeMount := common.GenerateNRIvol(ds.Spec.Selector.MatchLabels["kubearmor.io/nri-socket"])
					if common.NRIEnabled {
						// update daemonset volumeMount and volumes
						common.AddOrRemoveVolumeMount(&NRIVolumeMount, &ds.Spec.Template.Spec.Containers[0].VolumeMounts, common.AddAction)
						common.AddOrRemoveVolume(&NRIVolume, &ds.Spec.Template.Spec.Volumes, common.AddAction)
					} else {
						// update daemonset volumeMount and volumes
						common.AddOrRemoveVolumeMount(&NRIVolumeMount, &ds.Spec.Template.Spec.Containers[0].VolumeMounts, common.DeleteAction)
						common.AddOrRemoveVolume(&NRIVolume, &ds.Spec.Template.Spec.Volumes, common.DeleteAction)
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
		case "relay":
			relay, err := clusterWatcher.Client.AppsV1().Deployments(common.Namespace).Get(context.Background(), deployments.RelayDeploymentName, v1.GetOptions{})
			if err != nil {
				clusterWatcher.Log.Warnf("Cannot get deployment=%s error=%s", deployments.RelayDeploymentName, err.Error())
				res = err
			} else {
				relay.Spec.Template.Spec.Containers[0].Image = common.GetApplicationImage(common.KubeArmorRelayName)
				relay.Spec.Template.Spec.Containers[0].ImagePullPolicy = corev1.PullPolicy(common.KubeArmorRelayImagePullPolicy)
				relay.Spec.Template.Spec.Containers[0].Args = common.KubeArmorRelayArgs
				relay.Spec.Template.Spec.ImagePullSecrets = common.KubeArmorRelayImagePullSecrets
				if len(relay.Spec.Template.Spec.ImagePullSecrets) < 1 {
					utils.UpdateImagePullSecretFromGlobal(common.GlobalImagePullSecrets, &relay.Spec.Template.Spec.ImagePullSecrets)
				}
				if len(relay.Spec.Template.Spec.ImagePullSecrets) == 0 && len(ImagePullSecrets) > 0 {
					UpdateImagePullSecretsIfDefinedAndUpdated(&relay.Spec.Template.Spec.ImagePullSecrets, ImagePullSecrets)
				}
				relay.Spec.Template.Spec.Tolerations = common.KubeArmorRelayTolerations
				if len(relay.Spec.Template.Spec.Tolerations) < 1 {
					utils.UpdateTolerationFromGlobal(common.GlobalTolerations, &relay.Spec.Template.Spec.Tolerations)
				}

				// update with globalNodeSelector
				AddOrUpdateNodeSelector(relay.Spec.Template.Spec.NodeSelector, common.GlobalNodeSelectors)
				// add/override with relay specific nodeSelector
				if len(common.KubeArmorRelayNodeSelector) > 0 {
					defer RemoveDeletedEntriesForNodeSelector(common.KubeArmorRelayNodeSelector)
					AddOrUpdateNodeSelector(relay.Spec.Template.Spec.NodeSelector, common.KubeArmorRelayNodeSelector)
				}

				// update with global env
				AddOrUpdateEnv(&relay.Spec.Template.Spec.Containers[0].Env, common.GlobalEnv)
				// add/override with relay specific env
				if len(common.KubeArmorRelayEnv) > 0 {
					defer RemoveDeletedEntriesForEnv(&common.KubeArmorRelayEnv)
					AddOrUpdateEnv(&relay.Spec.Template.Spec.Containers[0].Env, common.KubeArmorRelayEnv)
				}

				_, err = clusterWatcher.Client.AppsV1().Deployments(common.Namespace).Update(context.Background(), relay, v1.UpdateOptions{})
				if err != nil {
					clusterWatcher.Log.Warnf("Cannot update deployment=%s error=%s", deployments.RelayDeploymentName, err.Error())
					res = err
				} else {
					clusterWatcher.Log.Infof("Updated Deployment=%s with image=%s", deployments.RelayDeploymentName, common.KubeArmorRelayImage)
				}
			}

		case "controller":
			dep, err := clusterWatcher.Client.AppsV1().Deployments(common.Namespace).Get(context.Background(), deployments.KubeArmorControllerDeploymentName, v1.GetOptions{})
			if err != nil {
				clusterWatcher.Log.Warnf("Cannot get deployment=%s error=%s", deployments.KubeArmorControllerDeploymentName, err.Error())
				res = err
			} else {
				controller := dep.DeepCopy()
				controller.Spec.Template.Spec.ImagePullSecrets = common.KubeArmorControllerImagePullSecrets
				if len(controller.Spec.Template.Spec.ImagePullSecrets) == 0 && len(ImagePullSecrets) > 0 {
					UpdateImagePullSecretsIfDefinedAndUpdated(&controller.Spec.Template.Spec.ImagePullSecrets, ImagePullSecrets)
				}
				if len(controller.Spec.Template.Spec.ImagePullSecrets) < 1 {
					utils.UpdateImagePullSecretFromGlobal(common.GlobalImagePullSecrets, &controller.Spec.Template.Spec.ImagePullSecrets)
				}
				if len(controller.Spec.Template.Spec.ImagePullSecrets) == 0 && len(ImagePullSecrets) > 0 {
					UpdateImagePullSecretsIfDefinedAndUpdated(&controller.Spec.Template.Spec.ImagePullSecrets, ImagePullSecrets)
				}
				controller.Spec.Template.Spec.Tolerations = common.KubeArmorControllerTolerations
				if len(controller.Spec.Template.Spec.Tolerations) < 1 {
					utils.UpdateTolerationFromGlobal(common.GlobalTolerations, &controller.Spec.Template.Spec.Tolerations)
				}
				containers := &controller.Spec.Template.Spec.Containers
				for i, container := range *containers {
					if container.Name == "manager" {
						(*containers)[i].Image = common.GetApplicationImage(common.KubeArmorControllerName)
						(*containers)[i].ImagePullPolicy = corev1.PullPolicy(common.KubeArmorControllerImagePullPolicy)
						(*containers)[i].Args = common.KubeArmorControllerArgs
						(*containers)[i].Ports[0].ContainerPort = int32(common.KubeArmorControllerPort)
					}
				}
				UpdateArgsIfDefinedAndUpdated(&controller.Spec.Template.Spec.Containers[0].Args, []string{"webhook-port=" + strconv.Itoa(common.KubeArmorControllerPort)})

				// update with globalNodeSelector
				AddOrUpdateNodeSelector(controller.Spec.Template.Spec.NodeSelector, common.GlobalNodeSelectors)
				// add/override with controller specific nodeSelector
				if len(common.KubeArmorControllerNodeSelector) > 0 {
					defer RemoveDeletedEntriesForNodeSelector(common.KubeArmorControllerNodeSelector)
					AddOrUpdateNodeSelector(controller.Spec.Template.Spec.NodeSelector, common.KubeArmorControllerNodeSelector)
				}

				// update with global env
				AddOrUpdateEnv(&controller.Spec.Template.Spec.Containers[0].Env, common.GlobalEnv)
				// add/override with controller specific env
				if len(common.KubeArmorControllerEnv) > 0 {
					defer RemoveDeletedEntriesForEnv(&common.KubeArmorControllerEnv)
					AddOrUpdateEnv(&controller.Spec.Template.Spec.Containers[0].Env, common.KubeArmorControllerEnv)
				}

				_, err := clusterWatcher.Client.AppsV1().Deployments(common.Namespace).Update(context.Background(), controller, v1.UpdateOptions{})
				if err != nil {
					clusterWatcher.Log.Warnf("Cannot update deployment=%s error=%s", deployments.KubeArmorControllerDeploymentName, err.Error())
					res = err
				} else {
					clusterWatcher.Log.Infof("Updated Deployment=%s", deployments.KubeArmorControllerDeploymentName)
				}
			}
		}
	}

	// this should be the last step after all updates are done
	if len(common.GlobalNodeSelectors) > 0 {
		RemoveDeletedEntriesForNodeSelector(common.GlobalNodeSelectors)
	}
	if len(common.GlobalEnv) > 0 {
		RemoveDeletedEntriesForEnv(&common.GlobalEnv)
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

		// we've replaced envs in previous step
		// let's update the envs from kubearmorconfig
		AddOrUpdateEnv(&relay.Spec.Template.Spec.Containers[0].Env, common.GlobalEnv)
		AddOrUpdateEnv(&relay.Spec.Template.Spec.Containers[0].Env, common.KubeArmorRelayEnv)

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
			relay.Spec.Template.Spec.Containers[0].Env = append(relay.Spec.Template.Spec.Containers[0].Env, corev1.EnvVar{
				Name:  "ES_CA_CERT_PATH",
				Value: common.ElasticSearchAdapterCaCertPath + "/" + common.Adapter.ElasticSearch.Auth.CaCertKey,
			})

			common.AddOrRemoveVolume(&ElasticSearchAdapterCaVolume, &relay.Spec.Template.Spec.Volumes, common.AddAction)
			common.AddOrRemoveVolumeMount(&ElasticSearchAdapterCaVolumeMount, &relay.Spec.Template.Spec.Containers[0].VolumeMounts, common.AddAction)
		} else {
			common.AddOrRemoveVolume(&ElasticSearchAdapterCaVolume, &relay.Spec.Template.Spec.Volumes, common.DeleteAction)
			common.AddOrRemoveVolumeMount(&ElasticSearchAdapterCaVolumeMount, &relay.Spec.Template.Spec.Containers[0].VolumeMounts, common.DeleteAction)
		}

		if common.Adapter.ElasticSearch.Auth.AllowTlsInsecure {
			relay.Spec.Template.Spec.Containers[0].Env = append(relay.Spec.Template.Spec.Containers[0].Env, corev1.EnvVar{
				Name:  "ES_ALLOW_INSECURE_TLS",
				Value: "true",
			})
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

func UpdateNodeSelectorIfDefinedAndUpdated(common map[string]string, in map[string]string) bool {
	var deleted = false
	// mark deleted entries
	for k := range common {
		if _, ok := in[k]; !ok {
			deleted = true
			common[k] = "-"
		}
	}

	if len(in) == 0 {
		return false || deleted
	}

	if !reflect.DeepEqual(common, in) {
		for k, v := range in {
			common[k] = v
		}
		return true
	}
	return false || deleted
}

func UpdateEnvIfDefinedAndUpdated(defaultEnv *[]corev1.EnvVar, in []corev1.EnvVar) bool {
	// mark deleted entries
	var deleted = false

	for i, env := range *defaultEnv {
		if idx := slices.IndexFunc(in, func(e corev1.EnvVar) bool {
			return e.Name == env.Name
		}); idx < 0 {
			(*defaultEnv)[i].Value = "-"
			deleted = true
		}
	}

	if len(in) == 0 {
		return false || deleted
	}

	var changed = false
	// update or add
	for _, env := range in {
		if idx := slices.IndexFunc(*defaultEnv, func(e corev1.EnvVar) bool {
			return e.Name == env.Name
		}); idx >= 0 {
			if (*defaultEnv)[idx].Value != env.Value {
				(*defaultEnv)[idx].Value = env.Value
				changed = true
			}
		} else {
			*defaultEnv = append(*defaultEnv, env)
			changed = true
		}
	}

	return changed || deleted
}

func AddOrUpdateNodeSelector(dst map[string]string, src map[string]string) {
	if dst == nil {
		return
	}

	deletedEntries := []string{}
	// add or update
	for k, v := range src {
		if v == "-" {
			deletedEntries = append(deletedEntries, k)
		}
		dst[k] = v
	}

	// remove deleted entries from dst
	for _, ent := range deletedEntries {
		delete(dst, ent)
	}
}

func AddOrUpdateEnv(dst *[]corev1.EnvVar, src []corev1.EnvVar) {

	if dst == nil {
		return
	}

	deletedEntries := []string{}

	// add or update
	for _, env := range src {
		if env.Value == "-" {
			deletedEntries = append(deletedEntries, env.Name)
		}
		if idx := slices.IndexFunc(*dst, func(e corev1.EnvVar) bool {
			return e.Name == env.Name
		}); idx >= 0 {
			if (*dst)[idx].Value != env.Value {
				(*dst)[idx].Value = env.Value
			}
		} else {
			*dst = append(*dst, env)
		}
	}

	// remove deleted entries from dst
	for _, val := range deletedEntries {
		*dst = slices.DeleteFunc(*dst, func(e corev1.EnvVar) bool {
			return e.Name == val
		})
	}
}

func RemoveDeletedEntriesForNodeSelector(ns map[string]string) {
	deletedEntries := []string{}

	for _, v := range ns {
		if v == "-" {
			deletedEntries = append(deletedEntries, v)
		}
	}

	for _, k := range deletedEntries {
		delete(ns, k)
	}
}

func RemoveDeletedEntriesForEnv(env *[]corev1.EnvVar) {
	*env = slices.DeleteFunc(*env, func(e corev1.EnvVar) bool {
		return e.Value == "-"
	})
}

func UpdateArgsIfDefinedAndUpdated(defaultArgs *[]string, in []string) bool {

	// If no user arguments provided, return defaults
	if len(in) == 0 {
		return false
	}

	// Create a map to track argument keys
	argMap := make(map[string]string)

	// Parse default arguments into map
	for _, arg := range *defaultArgs {
		if key, value, found := common.ParseArgument(arg); found {
			argMap[key] = value
		}
	}

	// Override with user-provided arguments
	for _, arg := range in {
		if key, value, found := common.ParseArgument(arg); found {
			argMap[key] = value
		} else {
			// If argument doesn't follow key=value format, append it as is
			*defaultArgs = append(*defaultArgs, arg)
		}
	}

	// Convert map back to slice of arguments
	var finalArgs []string
	for key, value := range argMap {
		finalArgs = append(finalArgs, fmt.Sprintf("-%s=%s", key, value))
	}

	// Sort for consistency
	sort.Strings(finalArgs)

	if !reflect.DeepEqual(*defaultArgs, finalArgs) {
		*defaultArgs = finalArgs
		return true
	}

	return false
}

func UpdateImagePullSecretsIfDefinedAndUpdated(common *[]corev1.LocalObjectReference, in []corev1.LocalObjectReference) bool {
	if len(in) != len(*common) {
		*common = in
		return true
	}
	for _, sec := range in {
		if !slices.Contains(*common, sec) {
			*common = in
			return true
		}
	}
	return false
}

func UpdateTolerationsIfDefinedAndUpdated(common *[]corev1.Toleration, in []corev1.Toleration) bool {
	if len(in) != len(*common) {
		*common = in
		return true
	}
	for _, sec := range in {
		if !slices.Contains(*common, sec) {
			*common = in
			return true
		}
	}
	return false
}

func UpdateNRIAvailabilityIfDefinedAndUpdated(common *bool, in bool) bool {
	if in != *common {
		*common = in
		return true
	}
	return false
}

func UpdateImages(config *opv1.KubeArmorConfigSpec) []string {
	updatedImages := []string{}
	// if kubearmor image or imagePullPolicy got updated
	if UpdateIfDefinedAndUpdated(&common.KubeArmorImage, config.KubeArmorImage.Image) ||
		UpdateIfDefinedAndUpdated(&common.KubeArmorImagePullPolicy, config.KubeArmorImage.ImagePullPolicy) ||
		UpdateArgsIfDefinedAndUpdated(&common.KubeArmorArgs, config.KubeArmorImage.Args) ||
		UpdateImagePullSecretsIfDefinedAndUpdated(&common.KubeArmorImagePullSecrets, config.KubeArmorImage.ImagePullSecrets) ||
		UpdateTolerationsIfDefinedAndUpdated(&common.KubeArmorTolerations, config.KubeArmorImage.Tolerations) ||
		UpdateNRIAvailabilityIfDefinedAndUpdated(&common.NRIEnabled, config.EnableNRI) ||
		UpdateNodeSelectorIfDefinedAndUpdated(common.KubeArmorNodeSelector, config.KubeArmorImage.NodeSelector) ||
		UpdateEnvIfDefinedAndUpdated(&common.KubeArmorEnv, config.KubeArmorImage.Env) {
		updatedImages = append(updatedImages, "kubearmor")
	}
	// if kubearmor-init image or imagePullPolicy got updated
	if UpdateIfDefinedAndUpdated(&common.KubeArmorInitImage, config.KubeArmorInitImage.Image) ||
		UpdateIfDefinedAndUpdated(&common.KubeArmorInitImagePullPolicy, config.KubeArmorInitImage.ImagePullPolicy) ||
		UpdateArgsIfDefinedAndUpdated(&common.KubeArmorInitArgs, config.KubeArmorInitImage.Args) ||
		UpdateImagePullSecretsIfDefinedAndUpdated(&common.KubeArmorInitImagePullSecrets, config.KubeArmorInitImage.ImagePullSecrets) ||
		UpdateTolerationsIfDefinedAndUpdated(&common.KubeArmorInitTolerations, config.KubeArmorInitImage.Tolerations) ||
		UpdateEnvIfDefinedAndUpdated(&common.KubeArmorInitEnv, config.KubeArmorInitImage.Env) {
		updatedImages = append(updatedImages, "init")
	}
	// kubearmor-relay image or imagePullPolicy got updated
	if UpdateIfDefinedAndUpdated(&common.KubeArmorRelayImage, config.KubeArmorRelayImage.Image) ||
		UpdateIfDefinedAndUpdated(&common.KubeArmorRelayImagePullPolicy, config.KubeArmorRelayImage.ImagePullPolicy) ||
		UpdateArgsIfDefinedAndUpdated(&common.KubeArmorRelayArgs, config.KubeArmorRelayImage.Args) ||
		UpdateImagePullSecretsIfDefinedAndUpdated(&common.KubeArmorRelayImagePullSecrets, config.KubeArmorRelayImage.ImagePullSecrets) ||
		UpdateTolerationsIfDefinedAndUpdated(&common.KubeArmorRelayTolerations, config.KubeArmorRelayImage.Tolerations) ||
		UpdateNodeSelectorIfDefinedAndUpdated(common.KubeArmorRelayNodeSelector, config.KubeArmorRelayImage.NodeSelector) ||
		UpdateEnvIfDefinedAndUpdated(&common.KubeArmorRelayEnv, config.KubeArmorRelayImage.Env) {
		updatedImages = append(updatedImages, "relay")
	}
	// if kubearmor-controller image or imagePullPolicy got updated
	if UpdateIfDefinedAndUpdated(&common.KubeArmorControllerImage, config.KubeArmorControllerImage.Image) ||
		UpdateIfDefinedAndUpdated(&common.KubeArmorControllerImagePullPolicy, config.KubeArmorControllerImage.ImagePullPolicy) ||
		UpdateArgsIfDefinedAndUpdated(&common.KubeArmorControllerArgs, config.KubeArmorControllerImage.Args) ||
		UpdateImagePullSecretsIfDefinedAndUpdated(&common.KubeArmorControllerImagePullSecrets, config.KubeArmorControllerImage.ImagePullSecrets) ||
		UpdateTolerationsIfDefinedAndUpdated(&common.KubeArmorControllerTolerations, config.KubeArmorControllerImage.Tolerations) ||
		UpdateNodeSelectorIfDefinedAndUpdated(common.KubeArmorControllerNodeSelector, config.KubeArmorControllerImage.NodeSelector) ||
		UpdateEnvIfDefinedAndUpdated(&common.KubeArmorControllerEnv, config.KubeArmorControllerImage.Env) {
		updatedImages = append(updatedImages, "controller")
	}

	// if globalImagePullSecret or globalToleration updated
	if UpdateImagePullSecretsIfDefinedAndUpdated(&common.GlobalImagePullSecrets, config.GloabalImagePullSecrets) ||
		UpdateTolerationsIfDefinedAndUpdated(&common.GlobalTolerations, config.GlobalTolerations) ||
		UpdateNodeSelectorIfDefinedAndUpdated(common.GlobalNodeSelectors, config.GlobalNodeSelector) ||
		UpdateEnvIfDefinedAndUpdated(&common.GlobalEnv, config.GlobalEnv) {
		updatedImages = []string{"kubearmor", "init", "relay", "controller"}
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
			clusterWatcher.Log.Info("Config CR Status Updated Successfully")
		}
		return true, nil
	})
	if err != nil {
		clusterWatcher.Log.Errorf("Error updating the ConfigCR status %s", err)
		return
	}
}

func (clusterWatcher *ClusterWatcher) UpdateKubeArmorConfigMap(cfg *opv1.KubeArmorConfig) {
	err := wait.ExponentialBackoff(wait.Backoff{Steps: 5, Duration: 500 * time.Millisecond}, func() (bool, error) {
		cm, err := clusterWatcher.Client.CoreV1().ConfigMaps(common.Namespace).Get(context.Background(), deployments.KubeArmorConfigMapName, metav1.GetOptions{})
		if err != nil {
			if utils.IsNotfound(err) {
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

func (clusterWatcher *ClusterWatcher) WatchTlsState(tlsEnabled bool) error {
	var tlsState string
	update := false
	if tlsEnabled {
		tlsState = "-tlsEnabled=true"
	} else {
		tlsState = "-tlsEnabled=false"
	}
	relay, err := clusterWatcher.Client.AppsV1().Deployments(common.Namespace).Get(context.Background(), deployments.RelayDeploymentName, v1.GetOptions{})
	if err != nil {
		clusterWatcher.Log.Warnf("Cannot list KubeArmor relay deployment error=%s", err.Error())
		return err
	}
	dsList, err := clusterWatcher.Client.AppsV1().DaemonSets(common.Namespace).List(context.Background(), v1.ListOptions{
		LabelSelector: "kubearmor-app=kubearmor",
	})
	if err != nil {
		clusterWatcher.Log.Warnf("Cannot list KubeArmor daemonset(s) error=%s", err.Error())
		return err
	}
	for _, ds := range dsList.Items {
		if !(ds.Status.DesiredNumberScheduled == ds.Status.CurrentNumberScheduled &&
			slice.ContainsString(ds.Spec.Template.Spec.Containers[0].Args, tlsState, nil)) {
			update = true
		}
	}
	if !(relay.Status.Replicas == relay.Status.ReadyReplicas &&
		slice.ContainsString(relay.Spec.Template.Spec.Containers[0].Args, tlsState, nil)) {
		update = true
	}
	if tlsEnabled {
		if cert.CACert != nil {
			ca, err := clusterWatcher.Client.CoreV1().Secrets(common.Namespace).Get(context.Background(), common.KubeArmorCaSecretName, v1.GetOptions{})
			if err != nil && metav1errors.IsNotFound(err) {
				update = true
			} else {
				pemEncodedCert := certutil.GetPemCertFromx509Cert(*cert.CACert.Crt)
				if !bytes.Equal(ca.Data["tls.crt"], pemEncodedCert) {
					clusterWatcher.UpdateTlsConfigurations(false)
					update = true
				}
			}
		} else {
			update = true
		}

	}
	if update {
		return clusterWatcher.UpdateTlsConfigurations(tlsEnabled)
	}
	return nil
}
func (clusterWatcher *ClusterWatcher) UpdateWebhookSvcPort(port int) {
	// update webhook service port
	svc, err := clusterWatcher.Client.CoreV1().Services(common.Namespace).Get(context.Background(), common.KubeArmorControllerWebhookServiceName, v1.GetOptions{})
	if err != nil {
		clusterWatcher.Log.Warnf("Cannot get webhook service=%s error=%s", common.KubeArmorControllerWebhookServiceName, err.Error())
	} else {
		svc.Spec.Ports[0].TargetPort = intstr.FromInt(int(port))
		_, err = clusterWatcher.Client.CoreV1().Services(common.Namespace).Update(context.Background(), svc, v1.UpdateOptions{})
		if err != nil {
			clusterWatcher.Log.Warnf("Cannot update webhook service=%s error=%s", common.KubeArmorControllerWebhookServiceName, err.Error())
		} else {
			clusterWatcher.Log.Infof("Updated webhook service=%s", common.KubeArmorControllerWebhookServiceName)
		}
	}
}

func UpdateTlsArguments(args *[]string, action string) {
	if action == common.AddAction {
		common.AddOrReplaceArg("-tlsEnabled=true", "-tlsEnabled=false", args)
	} else if action == common.DeleteAction {
		common.AddOrReplaceArg("-tlsEnabled=false", "-tlsEnabled=true", args)
	}
}

func (clusterWatcher *ClusterWatcher) UpdateTlsVolumeAndVolumeMounts(action string) error {
	clusterWatcher.Log.Info("updating volume and volumemounts")
	// configure relay deployment and kubearmor daemonset
	relay, err := clusterWatcher.Client.AppsV1().Deployments(common.Namespace).Get(context.Background(), deployments.RelayDeploymentName, v1.GetOptions{})
	if err != nil {
		clusterWatcher.Log.Warnf("Cannot get deployment=%s error=%s", deployments.RelayDeploymentName, err.Error())
		return err
	} else {
		// update relay volumeMount and volumes
		common.AddOrRemoveVolumeMount(&common.KubeArmorRelayTlsVolumeMount, &relay.Spec.Template.Spec.Containers[0].VolumeMounts, action)
		common.AddOrRemoveVolume(&common.KubeArmorRelayTlsVolume, &relay.Spec.Template.Spec.Volumes, action)
		UpdateTlsArguments(&relay.Spec.Template.Spec.Containers[0].Args, action)
		_, err = clusterWatcher.Client.AppsV1().Deployments(common.Namespace).Update(context.Background(), relay, v1.UpdateOptions{})
		if err != nil {
			clusterWatcher.Log.Warnf("Cannot update deployment=%s error=%s", deployments.RelayDeploymentName, err.Error())
			return err
		} else {
			clusterWatcher.Log.Infof("Updated Deployment=%s", deployments.RelayDeploymentName)
		}
	}
	dsList, err := clusterWatcher.Client.AppsV1().DaemonSets(common.Namespace).List(context.Background(), v1.ListOptions{
		LabelSelector: "kubearmor-app=kubearmor",
	})
	if err != nil {
		clusterWatcher.Log.Warnf("Cannot list KubeArmor daemonset(s) error=%s", err.Error())
		return err
	} else {
		for _, ds := range dsList.Items {
			// update daemonset volumeMount and volumes
			common.AddOrRemoveVolumeMount(&common.KubeArmorCaVolumeMount, &ds.Spec.Template.Spec.Containers[0].VolumeMounts, action)
			common.AddOrRemoveVolume(&common.KubeArmorCaVolume, &ds.Spec.Template.Spec.Volumes, action)
			UpdateTlsArguments(&ds.Spec.Template.Spec.Containers[0].Args, action)
			_, err = clusterWatcher.Client.AppsV1().DaemonSets(common.Namespace).Update(context.Background(), &ds, v1.UpdateOptions{})
			if err != nil {
				clusterWatcher.Log.Warnf("Cannot update daemonset=%s error=%s", ds.Name, err.Error())
				return err
			} else {
				clusterWatcher.Log.Infof("Updated daemonset=%s", ds.Name)
			}
		}
	}
	return nil
}

func (clusterWatcher *ClusterWatcher) DeleteAllTlsSecrets() error {
	clusterWatcher.Log.Info("tls is disabled deleting secrets")
	tlsSecrets := []string{
		common.KubeArmorCaSecretName,
		common.KubeArmorClientSecretName,
		common.KubeArmorRelayServerSecretName,
	}
	for _, secret := range tlsSecrets {
		err := clusterWatcher.Client.CoreV1().Secrets(common.Namespace).Delete(context.Background(), secret, v1.DeleteOptions{})
		if err != nil {
			clusterWatcher.Log.Errorf("error while deleting secret: %s, error=%s", secret, err.Error())
			return err
		}
	}
	return nil
}

func (clusterWatcher *ClusterWatcher) UpdateTlsConfigurations(tlsEnabled bool) error {
	// if tls is enabled
	if tlsEnabled {
		// create cert secrets
		clusterWatcher.Log.Info("tls enabled creating secrets\n")
		tlsCertSecrets, err := cert.GetAllTlsCertSecrets()
		if err != nil {
			clusterWatcher.Log.Errorf("error while creating certificates: %s", err)
			return err
		}
		secrets := []*corev1.Secret{}
		for _, secret := range tlsCertSecrets {
			secrets = append(secrets, addOwnership(secret).(*corev1.Secret))
		}
		for _, s := range secrets {
			clusterWatcher.Log.Infof("creating secret: %s", s.Name)
			_, err := clusterWatcher.Client.CoreV1().Secrets(common.Namespace).Create(context.Background(), s, metav1.CreateOptions{})
			if err != nil {
				if metav1errors.IsAlreadyExists(err) {
					oldSecret, err := clusterWatcher.Client.CoreV1().Secrets(common.Namespace).Get(context.Background(), s.Name, metav1.GetOptions{})
					if err != nil {
						clusterWatcher.Log.Errorf("error while getting secret: %s, error=%s", s.Name, err)
						return err
					}
					oldSecret.Data = s.Data
					_, err = clusterWatcher.Client.CoreV1().Secrets(common.Namespace).Update(context.Background(), oldSecret, metav1.UpdateOptions{})
					if err != nil {
						clusterWatcher.Log.Warnf("Cannot update secret %s, error=%s", s.Name, err)
						return err
					}
					clusterWatcher.Log.Infof("Updated tls secret: %s", oldSecret.Name)
				} else {
					clusterWatcher.Log.Warnf("error while creating secret: %s, error=%s", s.Name, err)
					return err
				}
			} else {
				clusterWatcher.Log.Infof("created tls secret: %s", s.Name)
			}
		}
		// configure relay deployment and kubearmor daemonset
		clusterWatcher.UpdateTlsVolumeAndVolumeMounts(common.AddAction)
	} else {
		clusterWatcher.Log.Info("tls is disabled removing configs and secrets")
		clusterWatcher.UpdateTlsVolumeAndVolumeMounts(common.DeleteAction)
		// delete all tls secrets
		clusterWatcher.DeleteAllTlsSecrets()
	}
	return nil
}

func (clusterWatcher *ClusterWatcher) WatchRecommendedPolicies() error {
	var yamlBytes []byte
	policies, err := recommend.CRDFs.ReadDir(".")
	if err != nil {
		clusterWatcher.Log.Warnf("error reading policies FS %s", err)
		return err
	}
	for _, policy := range policies {
		csp := &secv1.KubeArmorClusterPolicy{}
		if !policy.IsDir() {
			yamlBytes, err = recommend.CRDFs.ReadFile(policy.Name())
			if err != nil {
				clusterWatcher.Log.Warnf("error reading csp %s", policy.Name())
				continue
			}
			if err := runtime.DecodeInto(scheme.Codecs.UniversalDeserializer(), yamlBytes, csp); err != nil {
				clusterWatcher.Log.Warnf("error decoding csp %s", policy.Name())
				continue
			}
		}
		switch common.RecommendedPolicies.Enable {
		case true:
			if slices.Contains(common.RecommendedPolicies.ExcludePolicy, csp.Name) {
				clusterWatcher.Log.Infof("excluding csp ", csp.Name)
				err = clusterWatcher.Secv1Client.SecurityV1().KubeArmorClusterPolicies().Delete(context.Background(), csp.GetName(), metav1.DeleteOptions{})
				if err != nil && !metav1errors.IsNotFound(err) {
					clusterWatcher.Log.Warnf("error deleting csp %s", csp.GetName())
				} else if err == nil {
					clusterWatcher.Log.Infof("deleted csp :%s", csp.GetName())
				}
				continue
			}
			csp.Spec.Selector.MatchExpressions = common.RecommendedPolicies.MatchExpressions
			csp.Annotations["app.kubernetes.io/managed-by"] = "kubearmor-operator"
			_, err = clusterWatcher.Secv1Client.SecurityV1().KubeArmorClusterPolicies().Create(context.Background(), csp, metav1.CreateOptions{})
			if err != nil && !metav1errors.IsAlreadyExists(err) {
				clusterWatcher.Log.Warnf("error creating csp %s", csp.GetName())
				continue
			} else if metav1errors.IsAlreadyExists(err) {
				pol, err := clusterWatcher.Secv1Client.SecurityV1().KubeArmorClusterPolicies().Get(context.Background(), csp.GetName(), metav1.GetOptions{})
				if err != nil {
					clusterWatcher.Log.Warnf("error getting csp %s", csp.GetName())
					continue
				}
				if !reflect.DeepEqual(pol.Spec.Selector.MatchExpressions, common.RecommendedPolicies.MatchExpressions) {
					pol.Spec.Selector.MatchExpressions = common.RecommendedPolicies.MatchExpressions
					_, err := clusterWatcher.Secv1Client.SecurityV1().KubeArmorClusterPolicies().Update(context.Background(), pol, metav1.UpdateOptions{})
					if err != nil {
						clusterWatcher.Log.Warnf("error updating csp %s", csp.GetName())
						continue
					} else {
						clusterWatcher.Log.Infof("updated csp %s", csp.GetName())
					}
				}
			} else {
				clusterWatcher.Log.Info("created csp", csp.GetName())
			}
		case false:
			if !policy.IsDir() {
				if pol, err := clusterWatcher.Secv1Client.SecurityV1().KubeArmorClusterPolicies().Get(context.Background(), csp.Name, v1.GetOptions{}); err == nil &&
					pol.Annotations["app.kubernetes.io/managed-by"] == "kubearmor-operator" {
					err = clusterWatcher.Secv1Client.SecurityV1().KubeArmorClusterPolicies().Delete(context.Background(), csp.GetName(), metav1.DeleteOptions{})
					if err != nil && !metav1errors.IsNotFound(err) {
						clusterWatcher.Log.Warnf("error deleting csp %s", csp.GetName())
						continue
					} else if err == nil {
						clusterWatcher.Log.Infof("deleted csp %s", csp.GetName())
					}
				} else if err != nil && !metav1errors.IsNotFound(err) {
					clusterWatcher.Log.Warnf("error getting csp: %v", err)
				}
			}
		}
	}

	return nil
}

func UpdateRecommendedPolicyConfig(config *opv1.KubeArmorConfigSpec) bool {
	updated := false
	if config.RecommendedPolicies.Enable != common.RecommendedPolicies.Enable {
		common.RecommendedPolicies.Enable = config.RecommendedPolicies.Enable
		updated = true
	}
	if !reflect.DeepEqual(config.RecommendedPolicies.MatchExpressions, common.RecommendedPolicies.MatchExpressions) {
		common.RecommendedPolicies.MatchExpressions = slices.Clone(config.RecommendedPolicies.MatchExpressions)
		updated = true
	}
	if !reflect.DeepEqual(config.RecommendedPolicies.ExcludePolicy, common.RecommendedPolicies.ExcludePolicy) {
		common.RecommendedPolicies.ExcludePolicy = slices.Clone(config.RecommendedPolicies.ExcludePolicy)
		updated = true
	}
	return updated
}

func UpdateConfigMapData(config *opv1.KubeArmorConfigSpec) bool {
	updated := false
	configMapData := ""

	if config.DefaultFilePosture != "" {
		if common.ConfigMapData[common.ConfigDefaultFilePosture] != string(config.DefaultFilePosture) {
			common.ConfigMapData[common.ConfigDefaultFilePosture] = string(config.DefaultFilePosture)
			updated = true
		}
		configMapData += fmt.Sprintf("%s: %s\n", common.ConfigDefaultFilePosture, config.DefaultFilePosture)
	}
	if config.DefaultCapabilitiesPosture != "" {
		if common.ConfigMapData[common.ConfigDefaultCapabilitiesPosture] != string(config.DefaultCapabilitiesPosture) {
			common.ConfigMapData[common.ConfigDefaultCapabilitiesPosture] = string(config.DefaultCapabilitiesPosture)
			updated = true
		}
		configMapData += fmt.Sprintf("%s: %s\n", common.ConfigDefaultCapabilitiesPosture, config.DefaultCapabilitiesPosture)
	}
	if config.DefaultNetworkPosture != "" {
		if common.ConfigMapData[common.ConfigDefaultNetworkPosture] != string(config.DefaultNetworkPosture) {
			common.ConfigMapData[common.ConfigDefaultNetworkPosture] = string(config.DefaultNetworkPosture)
			updated = true
		}
		configMapData += fmt.Sprintf("%s: %s\n", common.ConfigDefaultNetworkPosture, config.DefaultNetworkPosture)
	}
	DropResourceFromProcessLogs := strconv.FormatBool(config.DropResourceFromProcessLogs)
	if common.ConfigMapData[common.ConfigDropResourceFromProcessLogs] != DropResourceFromProcessLogs {
		common.ConfigMapData[common.ConfigDropResourceFromProcessLogs] = DropResourceFromProcessLogs
		updated = true
	}
	if config.DefaultVisibility != "" {
		if common.ConfigMapData[common.ConfigVisibility] != config.DefaultVisibility {
			common.ConfigMapData[common.ConfigVisibility] = config.DefaultVisibility
			updated = true
		}
		configMapData += fmt.Sprintf("%s: %s\n", common.ConfigVisibility, config.DefaultVisibility)
	}
	AlertThrottlingEnabled := strconv.FormatBool(config.AlertThrottling)
	if common.ConfigMapData[common.ConfigAlertThrottling] != AlertThrottlingEnabled {
		common.ConfigMapData[common.ConfigAlertThrottling] = AlertThrottlingEnabled
		updated = true
	}
	configMapData += fmt.Sprintf("%s: %t\n", common.ConfigAlertThrottling, config.AlertThrottling)

	MaxAlertPerSec := strconv.FormatInt(int64(config.MaxAlertPerSec), 10)
	if config.MaxAlertPerSec == 0 {
		MaxAlertPerSec = common.DefaultMaxAlertPerSec
	}
	if common.ConfigMapData[common.ConfigMaxAlertPerSec] != MaxAlertPerSec {
		common.ConfigMapData[common.ConfigMaxAlertPerSec] = MaxAlertPerSec
		updated = true
	}
	configMapData += fmt.Sprintf("%s: %s\n", common.ConfigMaxAlertPerSec, MaxAlertPerSec)

	ThrottleSec := strconv.FormatInt(int64(config.ThrottleSec), 10)
	if config.ThrottleSec == 0 {
		ThrottleSec = common.DefaultThrottleSec
	}
	if common.ConfigMapData[common.ConfigThrottleSec] != ThrottleSec {
		common.ConfigMapData[common.ConfigThrottleSec] = ThrottleSec
		updated = true
	}
	configMapData += fmt.Sprintf("%s: %s\n", common.ConfigThrottleSec, ThrottleSec)

	common.ConfigMapData[common.KubeArmorConfigFileName] = configMapData

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

	stringEnableElasticAdapter := strconv.FormatBool(config.Adapters.ElasticSearch.Enabled)
	if stringEnableElasticAdapter != "" {
		if common.Adapter.ElasticSearch.Enabled != config.Adapters.ElasticSearch.Enabled {
			updated = true
			common.Adapter.ElasticSearch.Enabled = config.Adapters.ElasticSearch.Enabled
		}
		if common.Adapter.ElasticSearch.Auth.AllowTlsInsecure != config.Adapters.ElasticSearch.Auth.AllowTlsInsecure {
			updated = true
			common.Adapter.ElasticSearch.Auth.AllowTlsInsecure = config.Adapters.ElasticSearch.Auth.AllowTlsInsecure
		}
		if common.Adapter.ElasticSearch.AlertsIndexName != config.Adapters.ElasticSearch.AlertsIndexName {
			updated = true
			common.Adapter.ElasticSearch.AlertsIndexName = config.Adapters.ElasticSearch.AlertsIndexName
		}
		if common.Adapter.ElasticSearch.Url != config.Adapters.ElasticSearch.Url {
			updated = true
			common.Adapter.ElasticSearch.Url = config.Adapters.ElasticSearch.Url
		}
		if config.Adapters.ElasticSearch.Auth.SecretName != "" && common.Adapter.ElasticSearch.Auth.SecretName != config.Adapters.ElasticSearch.Auth.SecretName {
			updated = true
			common.Adapter.ElasticSearch.Auth.SecretName = config.Adapters.ElasticSearch.Auth.SecretName
		}
		if config.Adapters.ElasticSearch.Auth.UserNameKey != "" && common.Adapter.ElasticSearch.Auth.UserNameKey != config.Adapters.ElasticSearch.Auth.UserNameKey {
			updated = true
			common.Adapter.ElasticSearch.Auth.UserNameKey = config.Adapters.ElasticSearch.Auth.UserNameKey
		}
		if config.Adapters.ElasticSearch.Auth.PasswordKey != "" && common.Adapter.ElasticSearch.Auth.PasswordKey != config.Adapters.ElasticSearch.Auth.PasswordKey {
			updated = true
			common.Adapter.ElasticSearch.Auth.PasswordKey = config.Adapters.ElasticSearch.Auth.PasswordKey
		}
		if config.Adapters.ElasticSearch.Auth.CAcertSecretName != "" && common.Adapter.ElasticSearch.Auth.CAcertSecretName != config.Adapters.ElasticSearch.Auth.CAcertSecretName {
			updated = true
			common.Adapter.ElasticSearch.Auth.CAcertSecretName = config.Adapters.ElasticSearch.Auth.CAcertSecretName
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

func UpdateTlsData(config *opv1.KubeArmorConfigSpec) bool {
	updated := false
	if config.Tls.Enable != common.EnableTls {
		fmt.Printf("tls config changed: %v", config.Tls.Enable)
		common.EnableTls = config.Tls.Enable
		updated = true
	}

	if len(config.Tls.RelayExtraDnsNames) > 0 {
		common.ExtraDnsNames = config.Tls.RelayExtraDnsNames
	}

	if len(config.Tls.RelayExtraIpAddresses) > 0 {
		common.ExtraDnsNames = config.Tls.RelayExtraIpAddresses
	}

	return updated
}
