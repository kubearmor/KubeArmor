// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package helm

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/Masterminds/semver/v3"
)

var cfg = Controller{
	nodeConfigValues: map[string]interface{}{
		"nodes": []map[string]interface{}{
			{
				"config": map[string]interface{}{
					"enforcer":   "bpf",
					"runtime":    "cri-o",
					"socket":     "run_crio_crio.sock",
					"btf":        "yes",
					"apparmorfs": "yes",
					"arch":       "amd64",
					"seccomp":    "no",
				},
			},
		},
	},
	kaConfigValues: map[string]interface{}{
		"kubearmorRelay": map[string]interface{}{
			"enabled": true,
			"image": map[string]interface{}{
				"repository": "kubearmor/kubearmor-relay-server",
				"tag":        "stable",
			},
		},
	},
}

func TestUpdateNodeConfigHelmValues(t *testing.T) {
	newNodeConfig := []map[string]interface{}{
		{
			"config": map[string]interface{}{
				"enforcer":   "bpf",
				"runtime":    "cri-o",
				"socket":     "run_crio_crio.sock",
				"btf":        "yes",
				"apparmorfs": "yes",
				"arch":       "amd64",
				"seccomp":    "no",
			},
		},
		{
			"config": map[string]interface{}{
				"enforcer":   "apparmor",
				"runtime":    "containerd",
				"socket":     "var_run_containerd_containerd.sock",
				"btf":        "no",
				"apparmorfs": "yes",
				"arch":       "amd64",
				"seccomp":    "no",
			},
		},
	}

	cfg.UpdateNodeConfigHelmValues(newNodeConfig)
	updatedNodeConfigValues := cfg.nodeConfigValues["nodes"].([]map[string]interface{})
	assert.Equal(t, 2, len(updatedNodeConfigValues))
	assert.EqualValues(t, newNodeConfig, updatedNodeConfigValues)

}

func TestSemver(t *testing.T) {
	v134, _ := semver.NewVersion("v1.3.4")
	v138, _ := semver.NewVersion("v1.3.8")
	assert.Equal(t, true, v134.LessThan(v138))
}

func TestMergeMaps(t *testing.T) {
	originalMap := map[string]interface{}{
		"image": map[string]interface{}{
			"repository": "kubearmor/kubearmor",
			"tag":        "latest",
		},
	}

	updatedMap := map[string]interface{}{
		"image": map[string]interface{}{
			"tag": "stable",
		},
	}

	mergedMap := mergeMaps(originalMap, updatedMap)
	assert.Equal(t, "stable", mergedMap["image"].(map[string]interface{})["tag"])
	assert.Equal(t, "kubearmor/kubearmor", mergedMap["image"].(map[string]interface{})["repository"])

	mergedValsMap := mergeMaps(cfg.nodeConfigValues, cfg.kaConfigValues)
	assert.NotEqual(t, 0, len(mergedValsMap))
}

func TestMergeGlobalRegistryValueMap(t *testing.T) {
	vals := map[string]interface{}{
		"globalRegistry": "kubearmor",
	}
	vals = mergeMaps(vals, getGlobalRegistryValueMap("public.ecr.aws/kubearmor"))
	assert.Equal(t, "public.ecr.aws/kubearmor", vals["globalRegistry"])
}
