// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package policy

import (
	"context"
	"encoding/json"

	kg "github.com/kubearmor/KubeArmor/KubeArmor/log"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
	pb "github.com/kubearmor/KubeArmor/protobuf"
)

// ServiceServer provides structure to serve Policy gRPC service
type ServiceServer struct {
	pb.PolicyServiceServer
	UpdateHostPolicy      func(tp.K8sKubeArmorHostPolicyEvent)
	UpdateContainerPolicy func(tp.K8sKubeArmorPolicyEvent)
}

// HostPolicy accepts host policy event on gRPC service and updates host security policies. It responds with 1 if success else 0.
func (p *ServiceServer) HostPolicy(c context.Context, data *pb.Policy) (*pb.Response, error) {
	policyEvent := tp.K8sKubeArmorHostPolicyEvent{}
	res := new(pb.Response)

	err := json.Unmarshal(data.Policy, &policyEvent)
	if err == nil {
		p.UpdateHostPolicy(policyEvent)
		res.Status = 1
	} else {
		kg.Warn("Invalid Host Policy Event")
		res.Status = 0
	}

	return res, nil
}

// ContainerPolicy accepts container events on gRPC and update container security policies
func (p *ServiceServer) ContainerPolicy(c context.Context, data *pb.Policy) (*pb.Response, error) {
	policyEvent := tp.K8sKubeArmorPolicyEvent{}
	res := new(pb.Response)

	err := json.Unmarshal(data.Policy, &policyEvent)
	if err == nil {
		p.UpdateContainerPolicy(policyEvent)
		res.Status = 1
	} else {
		kg.Warn("Invalid Container Policy Event")
		res.Status = 0
	}

	return res, nil
}
