// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package base

import (
	"strconv"
	"strings"

	"github.com/kubearmor/KubeArmor/KubeArmor/buildinfo"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

func AddPolicyLogInfo(log *tp.Log, ckv *ContainerVal) {
	log.PolicyName = ckv.Policy.PolicyName
	if len(ckv.Policy.Tags) > 0 {
		log.Tags = strings.Join(ckv.Policy.Tags[:], ",")
		log.ATags = ckv.Policy.Tags
	}
	log.Severity = ckv.Policy.Severity
	log.Message = ckv.Policy.Message
	log.Type = "MatchedPolicy"
	log.KubeArmorVersion = buildinfo.GitSummary
}
func UpdateMatchPolicy(ckv *ContainerVal, secPolicy *tp.SecurityPolicy) {
	ckv.Policy.PolicyName = secPolicy.Metadata["policyName"]
	ckv.Policy.Severity = strconv.Itoa(secPolicy.Spec.Severity)
	ckv.Policy.Message = secPolicy.Spec.Message
	ckv.Policy.Tags = secPolicy.Spec.Tags
}
