package controllers

import (
	"context"
	"strings"
	"sync"

	"github.com/kubearmor/KubeArmor/pkg/KubeArmorOperator/common"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
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
	Daemonsets     map[string]int
	DaemonsetsLock *sync.Mutex
}
type Node struct {
	Name           string
	Enforcer       string
	Runtime        string
	RuntimeSocket  string
	RuntimeStorage string
	Arch           string
}

func NewClusterWatcher(client *kubernetes.Clientset, log *zap.SugaredLogger, pathPrefix, deploy_name string) *ClusterWatcher {
	if informer == nil {
		informer = informers.NewSharedInformerFactory(client, 0)
	}
	if deployment_uuid == "" {
		deploy, err := client.AppsV1().Deployments(common.Namespace).Get(context.Background(), deployment_name, v1.GetOptions{})
		if err != nil {
			log.Warnf("Cannot get deployment %s, error=%s", deployment_name, err.Error())
		} else {
			deployment_uuid = deploy.GetUID()
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
	}
}

func (clusterWatcher *ClusterWatcher) WatchNodes() {
	log := clusterWatcher.Log
	nodeInformer := informer.Core().V1().Nodes().Informer()
	nodeInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			if node, ok := obj.(*corev1.Node); ok {
				if val, ok := node.Labels[common.OsLabel]; ok && val == "linux" {
					log.Infof("Installing snitch on node %s", node.Name)
					_, err := clusterWatcher.Client.BatchV1().Jobs("kube-system").Create(context.Background(), deploySnitch(node.Name), v1.CreateOptions{})
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
					clusterWatcher.Log.Infof("Node %s was updated", node.Name)
					newNode := Node{}
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
					if val, ok := node.Labels[common.RuntimeStorageLabel]; ok {
						newNode.RuntimeStorage = val
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
					} else {
						if clusterWatcher.Nodes[i].Arch != newNode.Arch ||
							clusterWatcher.Nodes[i].Enforcer != newNode.Enforcer ||
							clusterWatcher.Nodes[i].Name != newNode.Name ||
							clusterWatcher.Nodes[i].Runtime != newNode.Runtime ||
							clusterWatcher.Nodes[i].RuntimeSocket != newNode.RuntimeSocket ||
							clusterWatcher.Nodes[i].RuntimeStorage != newNode.RuntimeStorage {
							clusterWatcher.Nodes[i] = newNode
							nodeModified = true
						}
					}
					clusterWatcher.NodesLock.Unlock()
					if nodeModified {
						clusterWatcher.UpdateDaemonsets(common.DeletAction, newNode.Enforcer, newNode.Runtime, newNode.RuntimeSocket, newNode.RuntimeStorage)
					}
					clusterWatcher.UpdateDaemonsets(common.AddAction, newNode.Enforcer, newNode.Runtime, newNode.RuntimeSocket, newNode.RuntimeStorage)
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
				clusterWatcher.UpdateDaemonsets(common.DeletAction, deletedNode.Enforcer, deletedNode.Runtime, deletedNode.RuntimeSocket, deletedNode.RuntimeStorage)
			}
		},
	})

	nodeInformer.Run(wait.NeverStop)
}

func (clusterWatcher *ClusterWatcher) UpdateDaemonsets(action, enforcer, runtime, socket, runtimeStorage string) {
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
	} else if action == common.DeletAction {
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
		daemonset := generateDaemonset(daemonsetName, enforcer, runtime, socket, runtimeStorage)
		_, err := clusterWatcher.Client.AppsV1().DaemonSets(common.Namespace).Create(context.Background(), daemonset, v1.CreateOptions{})
		if err != nil {
			clusterWatcher.Log.Warnf("Cannot Create daemonset %s, error=%s", daemonsetName, err.Error())
		}
	}

}
