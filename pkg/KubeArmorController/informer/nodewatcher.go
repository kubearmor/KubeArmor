package informer

import (
	"sync"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

type Cluster struct {
	Nodes             map[string]string
	HomogeneousStatus bool // the cluster runs the same enforcer
	ClusterLock       *sync.Mutex
	Enforcer          string
}

func InitCluster() Cluster {
	return Cluster{
		Nodes:             make(map[string]string),
		HomogeneousStatus: true,
		ClusterLock:       &sync.Mutex{},
		Enforcer:          "",
	}
}

func NodeWatcher(c *kubernetes.Clientset, cluster *Cluster, log logr.Logger) {
	log.Info("Starting node watcher")

	fact := informers.NewSharedInformerFactory(c, 0)
	inf := fact.Core().V1().Nodes().Informer()

	inf.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			if node, ok := obj.(*corev1.Node); ok {
				if node.Labels != nil {
					if enforcer, ok := node.Labels["kubearmor.io/enforcer"]; ok {
						cluster.ClusterLock.Lock()
						defer cluster.ClusterLock.Unlock()
						if len(cluster.Nodes) == 0 {
							cluster.HomogeneousStatus = true
							log.Info("Cluster in a homogeneus state, enabling mutation controller")
						} else if cluster.Enforcer != enforcer || !cluster.HomogeneousStatus {
							cluster.HomogeneousStatus = false
							log.Info("Cluster in a non homogeneus state, disabling mutation controller")
						}
						cluster.Enforcer = enforcer
						cluster.Nodes[node.Name] = enforcer
					}
				}
			}
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			if node, ok := newObj.(*corev1.Node); ok {
				if node.Labels == nil {
					return
				}
				cluster.ClusterLock.Lock()
				defer cluster.ClusterLock.Unlock()
				if _, ok := cluster.Nodes[node.Name]; !ok {
					return
				}

				if enforcer, ok := node.Labels["kubearmor.io/enforcer"]; ok {
					if enforcer != cluster.Nodes[node.Name] {
						cluster.Nodes[node.Name] = enforcer
						// re-compute homogeneous status
						homogeneous := true
						for _, nodeEnforcer := range cluster.Nodes {
							if enforcer != nodeEnforcer {
								homogeneous = false
								log.Info("Cluster in a non homogeneus state, disabling mutation controller")
								break
							}
						}
						cluster.HomogeneousStatus = homogeneous
						if homogeneous {
							cluster.Enforcer = enforcer
							log.Info("Cluster in a homogeneus state, enabling mutation controller")
						}
					}
				}
			}
		},
		DeleteFunc: func(obj interface{}) {
			if node, ok := obj.(*corev1.Node); ok {
				cluster.ClusterLock.Lock()
				defer cluster.ClusterLock.Unlock()

				delete(cluster.Nodes, node.Name)
				if len(cluster.Nodes) == 0 {
					return
				}
				// re-compute homogeneous status
				homogeneous := true
				first := true
				enforcer := ""
				for _, nodeEnforcer := range cluster.Nodes {
					if first {
						first = false
						enforcer = nodeEnforcer
						continue
					}
					if enforcer != nodeEnforcer {
						homogeneous = false
						log.Info("Cluster in a non homogeneus state, disabling mutation controller")
						break
					}
				}
				cluster.HomogeneousStatus = homogeneous
				if homogeneous {
					cluster.Enforcer = enforcer
					log.Info("Cluster in a homogeneus state, enabling mutation controller")
				}

			}
		},
	})

	inf.Run(wait.NeverStop)
}
