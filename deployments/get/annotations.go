// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package deployments

const (
	SelfProtectionAnnotation      = "kubearmor.io/self-protection"
	SelfProtectionEnabledValue    = "enabled"
	KubeArmorPolicyAnnotation     = "kubearmor-policy"
	KubeArmorPolicyEnabledValue   = "enabled"
	KubeArmorPolicyDisabledValue  = "disabled"
	KubeArmorPolicyAuditedValue   = "audited"
)

// SelfProtectionEnabled controls infra pod template annotations for operator-managed installs.
var SelfProtectionEnabled = false

// ApplyInfraPodPolicyAnnotations sets policy annotations on KubeArmor infrastructure pod templates.
func ApplyInfraPodPolicyAnnotations(annotations map[string]string, selfProtectionEnabled bool) map[string]string {
	if annotations == nil {
		annotations = map[string]string{}
	}

	if selfProtectionEnabled {
		annotations[SelfProtectionAnnotation] = SelfProtectionEnabledValue
		if annotations[KubeArmorPolicyAnnotation] != KubeArmorPolicyDisabledValue {
			annotations[KubeArmorPolicyAnnotation] = KubeArmorPolicyEnabledValue
		}
		return annotations
	}

	if annotations[KubeArmorPolicyAnnotation] != KubeArmorPolicyDisabledValue {
		annotations[KubeArmorPolicyAnnotation] = KubeArmorPolicyAuditedValue
	}

	return annotations
}

// InfraPodPolicyAnnotations returns default infra pod policy annotations.
func InfraPodPolicyAnnotations(selfProtectionEnabled bool) map[string]string {
	return ApplyInfraPodPolicyAnnotations(map[string]string{}, selfProtectionEnabled)
}
