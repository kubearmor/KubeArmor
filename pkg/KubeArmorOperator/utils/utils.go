// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor
package utils

import (
	"encoding/json"
	"regexp"
	"slices"
	"strings"

	opv1 "github.com/kubearmor/KubeArmor/pkg/KubeArmorOperator/api/operator.kubearmor.com/v1"
	"github.com/kubearmor/KubeArmor/pkg/KubeArmorOperator/common"
	corev1 "k8s.io/api/core/v1"
)

func ExtractVolumeFromMessage(message string) (string, bool) {
	// find volume name between quotes after "volume"
	// Message: MountVolume.SetUp failed for volume \"notexists-path\"
	re := regexp.MustCompile(`volume\s*\"([^\"]+)\"`)
	matches := re.FindStringSubmatch(message)

	if len(matches) > 1 {
		return matches[1], true
	}
	return "", false
}
func ExtractPathFromMessage(message string) (string, bool) {
	// find mount path between quotes after "mkdir"
	// Message: failed to mkdir \"/etc/apparmor.d/\": mkdir /etc/apparmor.d/: read-only file system
	re := regexp.MustCompile(`mkdir\s+\"([^\"]+)\"`)
	matches := re.FindStringSubmatch(message)

	if len(matches) > 1 {
		return matches[1], true
	}
	return "", false
}
func SanitizePullSecrets(inputs []string) []corev1.LocalObjectReference {
	refs := []corev1.LocalObjectReference{}

	for _, raw := range inputs {
		// Parse each string as: [{"name":"secret1"}]
		var arr []map[string]interface{}

		if err := json.Unmarshal([]byte(raw), &arr); err != nil {
			return nil
		}

		// Extract "name"
		for _, item := range arr {
			if nameVal, ok := item["name"]; ok {
				if nameStr, ok := nameVal.(string); ok {
					refs = append(refs, corev1.LocalObjectReference{Name: nameStr})
				}
			}
		}
	}

	return refs
}
func UpdateImagePullSecretFromGlobal(global []corev1.LocalObjectReference, dst *[]corev1.LocalObjectReference) {
	for _, sec := range global {
		if !slices.Contains(*dst, sec) {
			*dst = append(*dst, sec)
		}
	}
}

func UpdateTolerationFromGlobal(global []corev1.Toleration, dst *[]corev1.Toleration) {
	for _, tol := range global {
		if !slices.Contains(*dst, tol) {
			*dst = append(*dst, tol)
		}
	}
}
func IsNotfound(err error) bool {
	return err != nil && strings.Contains(err.Error(), "not found")
}
func IsAlreadyExists(err error) bool {
	return err != nil && strings.Contains(err.Error(), "already exist")
}
func CheckNodeRestart(new, old *corev1.Node) bool {

	oldTaints := false
	newTaints := false

	for _, val := range old.Spec.Taints {
		if val.Key == common.NotreadyTaint || val.Key == common.UnreachableTaint || val.Key == common.UnschedulableTaint {
			oldTaints = true
			break
		}

	}
	for _, val := range new.Spec.Taints {
		if val.Key == common.NotreadyTaint || val.Key == common.UnreachableTaint || val.Key == common.UnschedulableTaint {
			newTaints = true
			break
		}
	}
	/* Based on observation that when a node is restarted an update event
	   is generated with old node having following node taints
	   "node.kubernetes.io/not-ready" , "node.kubernetes.io/unreachable", "node.kubernetes.io/unschedulable"
	   and new node having none of these taints
	*/
	if oldTaints && !newTaints {
		// node might have been restarted
		return true
	}

	return false
}
func UpdateControllerPort(config *opv1.KubeArmorConfigSpec) bool {
	updated := false
	if config.ControllerPort != 0 && config.ControllerPort != common.KubeArmorControllerPort {

		common.ControllerPortLock.Lock()
		common.KubeArmorControllerPort = config.ControllerPort
		common.ControllerPortLock.Unlock()
		updated = true
	}

	return updated
}
