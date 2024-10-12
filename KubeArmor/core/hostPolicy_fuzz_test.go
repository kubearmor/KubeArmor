// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of KubeArmor
package core

import (
	"context"
	"github.com/kubearmor/KubeArmor/KubeArmor/policy"
	pb "github.com/kubearmor/KubeArmor/protobuf"
	"testing"
)

func FuzzHostPolicy(f *testing.F) {
	data := &pb.Policy{
		Policy: []byte(`
apiVersion: security.kubearmor.com/v1
kind: KubeArmorHostPolicy
metadata:
  name: hsp-cve-2019-14271
spec:
  tags: ["CVE-2019-14271","docker-cp","libraries","docker-tar","root-code-execution"]
  message: "Alert! Docker Binary Has Been Executed."
  nodeSelector:
    matchLabels:
      kubernetes.io/hostname: gke-ubuntu #change with your hostname
  process:
    severity: 2
    matchPaths:
      - path: /usr/bin/docker
      - path: /usr/sbin/chroot
      - path: /usr/lib/tar
      - path: /usr/lib/chmod
    action: Block
  file:
    severity: 3
    matchDirectories:
      - dir: /lib/x86_64-linux-gnu/
      - dir: /var/log/
    action: Block
		`),
	}
	dm := NewKubeArmorDaemon()
	f.Add(data.Policy)
	f.Fuzz(func(t *testing.T, data []byte) {
		p := &policy.PolicyServer{
			UpdateHostPolicy:  dm.ParseAndUpdateHostSecurityPolicy,
			HostPolicyEnabled: true,
		}
		policy := &pb.Policy{
			Policy: data,
		}
		res, err := p.HostPolicy(context.Background(), policy)
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
		if res.Status != pb.PolicyStatus_Invalid && res.Status != pb.PolicyStatus_Applied {
			t.Errorf("Unexpected status: %v, %v", res.Status, data)
		}
	})
}
