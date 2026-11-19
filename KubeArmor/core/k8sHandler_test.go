// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package core

import (
	"encoding/json"
	"testing"
)

func TestAppArmorAnnotationsPatch(t *testing.T) {
	// profile name taken from a pod annotation, trying to break out of the
	// annotations object and add a container to the pod template
	injected := `x"}},"spec":{"containers":[{"name":"app","image":"evil"}]},"metadata":{"annotations":{"y":"z`

	for _, kind := range []string{"Deployment", "CronJob"} {
		patch, err := appArmorAnnotationsPatch(map[string]string{
			"app":     injected,
			"sidecar": "unconfined",
			"other":   "kubearmor-ns-deploy-other",
		}, kind)
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", kind, err)
		}

		var p struct {
			Spec map[string]json.RawMessage `json:"spec"`
		}
		if err := json.Unmarshal(patch, &p); err != nil {
			t.Fatalf("%s: patch is not valid JSON: %v (%s)", kind, err, patch)
		}

		templateRaw := p.Spec["template"]
		if kind == "CronJob" {
			var jt struct {
				Spec map[string]json.RawMessage `json:"spec"`
			}
			if err := json.Unmarshal(p.Spec["jobTemplate"], &jt); err != nil {
				t.Fatalf("%s: bad jobTemplate: %v", kind, err)
			}
			templateRaw = jt.Spec["template"]
		}

		var template map[string]map[string]map[string]string
		if err := json.Unmarshal(templateRaw, &template); err != nil {
			t.Fatalf("%s: template has unexpected shape: %v (%s)", kind, err, patch)
		}
		if len(template) != 1 || len(template["metadata"]) != 1 {
			t.Fatalf("%s: template has unexpected keys: %s", kind, patch)
		}

		want := map[string]string{
			"kubearmor-policy": "enabled",
			"container.apparmor.security.beta.kubernetes.io/app":   "localhost/" + injected,
			"container.apparmor.security.beta.kubernetes.io/other": "localhost/kubearmor-ns-deploy-other",
		}
		got := template["metadata"]["annotations"]
		if len(got) != len(want) {
			t.Fatalf("%s: got annotations %v, want %v", kind, got, want)
		}
		for k, v := range want {
			if got[k] != v {
				t.Errorf("%s: annotation %q = %q, want %q", kind, k, got[k], v)
			}
		}
	}
}
