// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package bpflsm

import (
	cm "github.com/kubearmor/KubeArmor/KubeArmor/common"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

func (be *BPFEnforcer) UpdateContainerRules(id string, securityPolicies []tp.SecurityPolicy) {
	for _, secPolicy := range securityPolicies {
		if len(secPolicy.Spec.Process.MatchPaths) > 0 {
			for _, path := range secPolicy.Spec.Process.MatchPaths {
				if len(path.FromSource) == 0 {
					be.Logger.Printf("Rule %d for %s - %s", cm.JHash([]byte(path.Path), 0), path.Path, id)
					be.ContainerMap[id].Map.Put(cm.JHash([]byte(path.Path), 0), [8]byte{})
				} else {
					for _, src := range path.FromSource {
						be.Logger.Printf("Rule %d for %s (%s) - %s", cm.JHash(append([]byte(path.Path), []byte(src.Path)...), 0), path.Path, src.Path, id)
						be.ContainerMap[id].Map.Put(cm.JHash(append([]byte(path.Path), []byte(src.Path)...), 0), [8]byte{})
					}
				}
			}
		}
	}
}
