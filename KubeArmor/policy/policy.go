// SPDX-License-Identifier: Apache-2.0
// Copyright 2026  Authors of KubeArmor

// Package policy handles policy updates over gRPC in non-k8s environment
package policy

import (
	"context"
	"encoding/json"

	kg "github.com/kubearmor/KubeArmor/KubeArmor/log"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
	pb "github.com/kubearmor/KubeArmor/protobuf"
)

// PolicyServer provides structure to serve Policy gRPC service
type PolicyServer struct {
	pb.PolicyServiceServer
	UpdateContainerPolicy  func(tp.K8sKubeArmorPolicyEvent) pb.PolicyStatus
	UpdateHostPolicy       func(tp.K8sKubeArmorHostPolicyEvent) pb.PolicyStatus
	ContainerPolicyEnabled bool
	HostPolicyEnabled      bool
}

// ContainerPolicy accepts container events on gRPC and update container security policies
func (p *PolicyServer) ContainerPolicy(c context.Context, data *pb.Policy) (*pb.Response, error) {
	res := new(pb.Response)
	if !p.ContainerPolicyEnabled {
		res.Status = pb.PolicyStatus_NotEnabled
		kg.Warn("Container policies are not enabled")
		return res, nil
	}
	policyEvent := tp.K8sKubeArmorPolicyEvent{}
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
func (p *PolicyServer) HostPolicy(c context.Context, data *pb.Policy) (*pb.Response, error) {
	res := new(pb.Response)
	if !p.HostPolicyEnabled {
		res.Status = pb.PolicyStatus_NotEnabled
		kg.Warn("Host policies are not enabled")
		return res, nil
	}
	policyEvent := tp.K8sKubeArmorHostPolicyEvent{}

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
