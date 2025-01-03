// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of KubeArmor

package config

import (
	"os"
	"testing"
	"fmt"
	"strings"
)

type ConfigParseError struct {
	err error
}

func (pe ConfigParseError) Error() string {
	return fmt.Sprintf("While parsing config: %s", pe.err.Error())
}

func LoadConfig_from_byteslice(data []byte) error {
    tempFile, err := os.CreateTemp(".", "kubearmor-*.yaml")
    if err != nil {
        return err
    }
    defer os.Remove(tempFile.Name())
	if _, err := tempFile.Write(data); err != nil {
        return err
	}
	os.Setenv("KUBEARMOR_CFG", tempFile.Name())
	return LoadConfig()
}

func FuzzConfig(f *testing.F){
    data1 := []byte(`
cluster: "default"
gRPC: "32767"
hostVisibility: "process,file,network,capabilities"
visibility: "process,file,network,capabilities"
enableKubeArmorHostPolicy: true
enableKubeArmorVm: false
k8s: false
alertThrottling: true
maxAlertPerSec: 10
throttleSec: 30
`)
f.Add(data1)
f.Fuzz(func(t *testing.T, data []byte) {
	err := LoadConfig_from_byteslice(data)
	if err != nil{
		if strings.Contains(err.Error(), "While parsing config:") {
			// Skip as these cases are handled by viper internally.
			t.Skipf("Skipping config parsing errors: %v", err)
			return
		}
		t.Errorf("Unexpected error: %v", err)
	}
})
}
