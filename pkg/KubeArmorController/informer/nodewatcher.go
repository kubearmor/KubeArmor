// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package informer

import (
	"fmt"
	"sync"

	"github.com/go-logr/logr"
	"github.com/kubearmor/KubeArmor/pkg/KubeArmorController/common"
	"github.com/kubearmor/KubeArmor/pkg/KubeArmorController/types"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

func InitCluster() types.Cluster {
	return types.Cluster{
		Nodes:              make(map[string]*types.NodeInfo),
		HomogeneousStatus:  true,
		ClusterLock:        &sync.RWMutex{},
		HomogenousApparmor: false,
		TotalNodes:         0,
	}
}

func NodeWatcher(c *kubernetes.Clientset, cluster *types.Cluster, log logr.Logger) {
	log.Info("Starting node watcher")

	fact := informers.NewSharedInformerFactory(c, 0)
	inf := fact.Core().V1().Nodes().Informer()

	inf.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			if node, ok := obj.(*corev1.Node); ok {
				if node.Labels != nil {
					if enforcer, ok := node.Labels["kubearmor.io/enforcer"]; ok {

						log.Info(fmt.Sprintf("New node was added, name=%s enforcer=%s", node.Name, enforcer))
						cluster.ClusterLock.Lock()
						defer cluster.ClusterLock.Unlock()
						cluster.TotalNodes++
						if enforcer == "apparmor" {

							cluster.Nodes[node.Name] = &types.NodeInfo{}
							cluster.Nodes[node.Name].Enforcer = enforcer

							kubearmorStatus, err := common.CheckKubearmorStatus(node.Name, c)
							if err != nil {
								log.Info(fmt.Sprintf("unable to get kubearmor status on node %s : %s", node.Name, err.Error()))
							}
							cluster.Nodes[node.Name].KubeArmorActive = kubearmorStatus
							if !cluster.Nodes[node.Name].KubeArmorActive {
								log.Info(fmt.Sprintf("kubearmor not found on node %s :", node.Name))
							}
						}
						// re-compute homogeneous status
						homogeneous := true
						homogeneousApparmor := false

						if len(cluster.Nodes) > 0 && cluster.TotalNodes != len(cluster.Nodes) {
							homogeneous = false
							log.Info(fmt.Sprintf("Cluster in a non homogeneus state with %d nodes", cluster.TotalNodes))
						}
						cluster.HomogeneousStatus = homogeneous

						if homogeneous {
							if enforcer == "apparmor" {
								homogeneousApparmor = true
								log.Info("Cluster in a homogeneus state with apparmor enforcer")
							} else {
								log.Info("Cluster in a homogeneus state")
							}
						}
						cluster.HomogenousApparmor = homogeneousApparmor
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

				if enforcer, ok := node.Labels["kubearmor.io/enforcer"]; ok {
					if _, ok := cluster.Nodes[node.Name]; ok {
						// in case the enforcer has been updated to bpflsm from apparmor
						if enforcer != cluster.Nodes[node.Name].Enforcer {
							delete(cluster.Nodes, node.Name)
						}
					}
					if enforcer == "apparmor" {
						if _, ok := cluster.Nodes[node.Name]; !ok {
							cluster.Nodes[node.Name] = &types.NodeInfo{}
						}
						cluster.Nodes[node.Name].Enforcer = enforcer
						var err error
						kubearmorStatus, err := common.CheckKubearmorStatus(node.Name, c)
						if err != nil {
							log.Error(err, fmt.Sprintf("unable to get kubearmor status on node %s", node.Name))
						}
						cluster.Nodes[node.Name].KubeArmorActive = kubearmorStatus

						if !cluster.Nodes[node.Name].KubeArmorActive {
							log.Info(fmt.Sprintf("kubearmor not found on node %s", node.Name))
						}
					}
					// re-compute homogeneous status
					homogeneous := true
					homogeneousApparmor := false

					if len(cluster.Nodes) > 0 && cluster.TotalNodes != len(cluster.Nodes) {
						homogeneous = false
						log.Info(fmt.Sprintf("Cluster in a non homogeneus state with %d nodes", cluster.TotalNodes))
					}

					cluster.HomogeneousStatus = homogeneous
					if homogeneous {
						if enforcer == "apparmor" {
							homogeneousApparmor = true
							log.Info("Cluster in a homogeneus state with apparmor enforcer")
						} else {
							log.Info("Cluster in a homogeneus state")
						}
					}
					cluster.HomogenousApparmor = homogeneousApparmor
				}
			}
		},
		DeleteFunc: func(obj interface{}) {
			if node, ok := obj.(*corev1.Node); ok {
				cluster.ClusterLock.Lock()
				defer cluster.ClusterLock.Unlock()

				cluster.TotalNodes--

				delete(cluster.Nodes, node.Name)

				if len(cluster.Nodes) == 0 && cluster.TotalNodes == 0 {
					return
				}
				// re-compute homogeneous status
				homogeneous := true
				homogeneousApparmor := false

				if len(cluster.Nodes) > 0 && cluster.TotalNodes != len(cluster.Nodes) {
					homogeneous = false
					log.Info(fmt.Sprintf("Cluster in a non homogeneus state with %d nodes", cluster.TotalNodes))
				}
				cluster.HomogeneousStatus = homogeneous
				if homogeneous {
					if cluster.TotalNodes == len(cluster.Nodes) {
						homogeneousApparmor = true
						log.Info("Cluster in a homogeneus state with apparmor enforcer")
					} else {
						log.Info("Cluster in a homogeneus state")
					}
				}
				cluster.HomogenousApparmor = homogeneousApparmor
			}
		},
	})

	inf.Run(wait.NeverStop)
}
