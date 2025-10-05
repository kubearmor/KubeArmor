// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor
package policy_test

import (
	"context"
	"encoding/json"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/kubearmor/KubeArmor/KubeArmor/core"
	"github.com/kubearmor/KubeArmor/KubeArmor/policy"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
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
	dm := core.NewKubeArmorDaemon()

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
	dm := core.NewKubeArmorDaemon()
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

func TestContainerPolicy(t *testing.T) {
	called := false
	mockUpdate := func(event tp.K8sKubeArmorPolicyEvent) pb.PolicyStatus {
		called = true
		return pb.PolicyStatus_Applied
	}

	tests := []struct {
		name       string
		enabled    bool
		input      []byte
		wantStatus pb.PolicyStatus
	}{
		{
			name:       "Disabled",
			enabled:    false,
			input:      []byte(`{}`),
			wantStatus: pb.PolicyStatus_NotEnabled,
		},
		{
			name:       "Invalid JSON",
			enabled:    true,
			input:      []byte(`invalid-json`),
			wantStatus: pb.PolicyStatus_Invalid,
		},
		{
			name:    "Empty metadata name",
			enabled: true,
			input: func() []byte {
				ev := tp.K8sKubeArmorPolicyEvent{
					Object: tp.K8sKubeArmorPolicy{
						Metadata: metav1.ObjectMeta{},
					},
				}
				b, _ := json.Marshal(ev)
				return b
			}(),
			wantStatus: pb.PolicyStatus_Invalid,
		},
		{
			name:    "Valid policy",
			enabled: true,
			input: func() []byte {
				ev := tp.K8sKubeArmorPolicyEvent{
					Object: tp.K8sKubeArmorPolicy{
						Metadata: metav1.ObjectMeta{Name: "test-policy"},
					},
				}
				b, _ := json.Marshal(ev)
				return b
			}(),
			wantStatus: pb.PolicyStatus_Applied,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			called = false
			s := &policy.PolicyServer{
				ContainerPolicyEnabled: tt.enabled,
				UpdateContainerPolicy:  mockUpdate,
			}
			res, err := s.ContainerPolicy(context.Background(), &pb.Policy{Policy: tt.input})
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if res.Status != tt.wantStatus {
				t.Errorf("got %v, want %v", res.Status, tt.wantStatus)
			}
			if tt.wantStatus == pb.PolicyStatus_Applied && !called {
				t.Errorf("expected UpdateContainerPolicy to be called")
			}
		})
	}
}

func TestHostPolicy(t *testing.T) {
	called := false
	mockUpdate := func(event tp.K8sKubeArmorHostPolicyEvent) pb.PolicyStatus {
		called = true
		return pb.PolicyStatus_Applied
	}

	tests := []struct {
		name       string
		enabled    bool
		input      []byte
		wantStatus pb.PolicyStatus
	}{
		{
			name:       "Disabled",
			enabled:    false,
			input:      []byte(`{}`),
			wantStatus: pb.PolicyStatus_NotEnabled,
		},
		{
			name:       "Invalid JSON",
			enabled:    true,
			input:      []byte(`invalid-json`),
			wantStatus: pb.PolicyStatus_Invalid,
		},
		{
			name:    "Empty metadata name",
			enabled: true,
			input: func() []byte {
				ev := tp.K8sKubeArmorHostPolicyEvent{
					Object: tp.K8sKubeArmorHostPolicy{
						Metadata: metav1.ObjectMeta{},
					},
				}
				b, _ := json.Marshal(ev)
				return b
			}(),
			wantStatus: pb.PolicyStatus_Invalid,
		},
		{
			name:    "Valid policy",
			enabled: true,
			input: func() []byte {
				ev := tp.K8sKubeArmorHostPolicyEvent{
					Object: tp.K8sKubeArmorHostPolicy{
						Metadata: metav1.ObjectMeta{Name: "host-policy"},
					},
				}
				b, _ := json.Marshal(ev)
				return b
			}(),
			wantStatus: pb.PolicyStatus_Applied,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			called = false
			s := &policy.PolicyServer{
				HostPolicyEnabled: tt.enabled,
				UpdateHostPolicy:  mockUpdate,
			}
			res, err := s.HostPolicy(context.Background(), &pb.Policy{Policy: tt.input})
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if res.Status != tt.wantStatus {
				t.Errorf("got %v, want %v", res.Status, tt.wantStatus)
			}
			if tt.wantStatus == pb.PolicyStatus_Applied && !called {
				t.Errorf("expected UpdateHostPolicy to be called")
			}
		})
	}
}
