// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package controller

import (
	"log"
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	nodes = []node{
		{
			Enforcer:      "bpf",
			Runtime:       "cri-o",
			RuntimeSocket: "run_crio_crio.sock",
			BTF:           "yes",
			ApparmorFs:    "yes",
			Seccomp:       "no",
		},
	}

	nodeInterfaceMap = []map[string]interface{}{
		{
			"apparmorfs": "yes",
			"arch":       "",
			"enforcer":   "bpf",
			"runtime":    "cri-o",
			"socket":     "run_crio_crio.sock",
			"btf":        "yes",
			"seccomp":    "no",
		},
	}
)

func TestGenerateNodeConfigHelmValues(t *testing.T) {
	nodemap := generateNodeConfigHelmValues(nodes)
	assert.NotNil(t, nodemap)
	assert.EqualValues(t, nodeInterfaceMap[0], nodemap[0]["config"])
	log.Printf("nodemap: %+v", nodemap)
}

func TestConvertNodeStructToMapOfStringInterface(t *testing.T) {
	mapInterface := convertNodeStructToMapOfStringInterface(nodes[0])
	assert.NotEqual(t, 0, len(mapInterface))
	log.Printf("nodeInterfaceMap: %+v", mapInterface)
}
