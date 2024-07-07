package policy

import (
	"context"
	"testing"

	pb "github.com/kubearmor/KubeArmor/protobuf"

	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

func mockUpdateContainerPolicy(policyEvent tp.K8sKubeArmorPolicyEvent) pb.PolicyStatus {
	return pb.PolicyStatus_Applied
}

func FuzzContainerPolicy(f *testing.F) {
	initialData := &pb.Policy{
		Policy: []byte(`{
			"type": "fuzz_test_seed",
			"object": {
				"metadata": {
					"name": "",
					"namespace": "multiubuntu"
				},
				"spec": {
					"selector": {
						"matchLabels": {
							"group": "group-1"
						}
					},
					"process": {
						"matchPaths": [
							{
								"path": "/bin/sleep"
							}
						]
					},
					"action": "Block"
				}
			}
		}`),
	}

	f.Add(initialData.Policy)

	f.Fuzz(func(t *testing.T, data []byte) {
		p := &PolicyServer{
			UpdateContainerPolicy: mockUpdateContainerPolicy,
		}
		policy := &pb.Policy{
			Policy: data,
		}
		res, err := p.ContainerPolicy(context.Background(), policy)
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
		if res.Status != pb.PolicyStatus_Invalid {
			t.Errorf("Unexpected status: %v, %v", res.Status, data)
		}
	})
}
