package common

import (
	"encoding/json"

	corev1 "k8s.io/api/core/v1"
)

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
