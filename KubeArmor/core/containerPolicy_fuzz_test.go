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
	Data1 := &pb.Policy{
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
	//ksp-group-2-allow-file-path-from-source-path.yaml
	Data2 := &pb.Policy{
		Policy: []byte(`
		apiVersion: security.kubearmor.com/v1
kind: KubeArmorPolicy
metadata:
  name: ksp-group-2-allow-file-path-from-source-path
  namespace: multiubuntu
spec:
  severity: 5
  message: "allow /bin/cat to access /secret.txt"
  selector:
    matchLabels:
      group: group-2
  process:
    matchDirectories:
      - dir: /bin/
        recursive: true
  file:
    matchPaths:
    - path: /secret.txt
      fromSource:
      - path: /bin/cat
    - path: /dev/tty
    - path: /lib/terminfo/x/xterm
    matchDirectories:
      - dir: /pts/
        recursive: true
      - dir: /proc/
        recursive: true
      - dir: /dev/
        recursive: true
      - dir: /lib/x86_64-linux-gnu/
      - dir: /bin/
  action:
    Allow
		`),
	}
	Data3 := &pb.Policy{
		Policy: []byte(`
		apiVersion: security.kubearmor.com/v1
kind: KubeArmorPolicy
metadata:
  name: ksp-ubuntu-1-allow-net-tcp-from-source
  namespace: multiubuntu
spec:
  severity: 8
  selector:
    matchLabels:
      container: ubuntu-1
  network:
    matchProtocols:
    - protocol: tcp
      fromSource:
      - path: /usr/bin/curl
  action: Allow
		`),
	}

	f.Add(Data1.Policy)
	f.Add(Data2.Policy)
	f.Add(Data3.Policy)
	dm := NewKubeArmorDaemon()

	f.Fuzz(func(t *testing.T, data []byte) {
		p := &policy.PolicyServer{
			UpdateContainerPolicy:  dm.ParseAndUpdateContainerSecurityPolicy,
			ContainerPolicyEnabled: true,
		}
		policy := &pb.Policy{
			Policy: data,
		}
		res, err := p.ContainerPolicy(context.Background(), policy)
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
		if res.Status != pb.PolicyStatus_Invalid && res.Status != pb.PolicyStatus_Applied && res.Status != pb.PolicyStatus_Modified {
			t.Errorf("Unexpected status: %v, %v", res.Status, data)
		}
	})
}
