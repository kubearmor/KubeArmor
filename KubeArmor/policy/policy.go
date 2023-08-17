// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

// Package policy handles policy updates over gRPC in non-k8s environment
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
	UpdateContainerPolicy func(tp.K8sKubeArmorPolicyEvent) pb.PolicyStatus
	UpdateHostPolicy      func(tp.K8sKubeArmorHostPolicyEvent) pb.PolicyStatus
}

// ContainerPolicy accepts container events on gRPC and update container security policies
func (p *ServiceServer) ContainerPolicy(c context.Context, data *pb.Policy) (*pb.Response, error) {
	policyEvent := tp.K8sKubeArmorPolicyEvent{}
	res := new(pb.Response)

	err := json.Unmarshal(data.Policy, &policyEvent)

	if err == nil {

		if policyEvent.Object.Metadata.Name != "" {

			res.Status = p.UpdateContainerPolicy(policyEvent)

		} else {
			res.Status = pb.PolicyStatus_Invalid
			kg.Warn("Empty Container Policy Event")
		}

	} else {

		kg.Warn("Invalid Container Policy Event")

		res.Status = pb.PolicyStatus_Invalid
	}

	return res, nil
}

// HostPolicy accepts host policy event on gRPC service and updates host security policies. It responds with 1 if success else 0.
func (p *ServiceServer) HostPolicy(c context.Context, data *pb.Policy) (*pb.Response, error) {

	policyEvent := tp.K8sKubeArmorHostPolicyEvent{}
	res := new(pb.Response)

	err := json.Unmarshal(data.Policy, &policyEvent)
	if err == nil {

		if policyEvent.Object.Metadata.Name != "" {

			res.Status = p.UpdateHostPolicy(policyEvent)

		} else {

			kg.Warn("Empty Host Policy Event")

			res.Status = pb.PolicyStatus_Invalid

		}

	} else {
		kg.Warn("Invalid Host Policy Event")
		res.Status = pb.PolicyStatus_Invalid
	}

	return res, nil
}
