// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of KubeArmor
package core

import (
	"context"
	"testing"

	"github.com/kubearmor/KubeArmor/KubeArmor/policy"
	pb "github.com/kubearmor/KubeArmor/protobuf"
)

func FuzzContainerPolicy(f *testing.F) {
	initialData := &pb.Policy{
		Policy: []byte(`
		apiVersion: security.kubearmor.com/v1
		kind: KubeArmorPolicy
		metadata:
		  name: ksp-group-1-proc-path-block
		  namespace: multiubuntu
		spec:
		  selector:
			matchLabels:
			  group: group-1
		  process:
			matchPaths:
			- path: /bin/sleep
		  action:
			Block
		`),
	}

	f.Add(initialData.Policy)
	dm := NewKubeArmorDaemon()

	f.Fuzz(func(t *testing.T, data []byte) {
		p := &policy.PolicyServer{
			UpdateContainerPolicy: dm.ParseAndUpdateContainerSecurityPolicy,
		}
		policy := &pb.Policy{
			Policy: data,
		}
		res, err := p.ContainerPolicy(context.Background(), policy)
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
		if res.Status != pb.PolicyStatus_Invalid && res.Status != pb.PolicyStatus_Applied && res.Status != pb.PolicyStatus_Modified{
			t.Errorf("Unexpected status: %v, %v", res.Status, data)
		}
	})
}
