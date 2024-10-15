// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor
package types

import (
	"sync"

	"github.com/go-logr/logr"
	"k8s.io/client-go/kubernetes"
	v1 "k8s.io/client-go/listers/core/v1"
)

type Cluster struct {
	Nodes              map[string]string
	HomogeneousStatus  bool // the cluster runs the same enforcer
	HomogenousApparmor bool // the cluster runs with apparmor enforcer
	ClusterLock        *sync.RWMutex
	TotalNodes         int //total no of nodes present
}

type MultiEnforcerController struct {
	Client    kubernetes.Clientset
	Log       logr.Logger
	Cluster   Cluster
	PodLister v1.PodLister
}
