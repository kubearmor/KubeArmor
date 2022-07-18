// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package core

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"

	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
)

type KarmorData struct {
	OSImage             string
	KernelVersion       string
	KubeletVersion      string
	ContainerRuntime    string
	SupportedLSMs       string
	KernelHeaderPresent bool
	HostSecurity        bool
	ContainerSecurity   bool
	KubeArmorPosture    KubeArmorPostures
}

type KubeArmorPostures struct {
	DefaultFilePosture             string
	DefaultNetworkPosture          string
	DefaultCapabilitiesPosture     string
	HostDefaultFilePosture         string
	HostDefaultNetworkPosture      string
	HostDefaultCapabilitiesPosture string
}

func SetKarmorData(dm *KubeArmorDaemon) KarmorData {
	var kd KarmorData
	var postures KubeArmorPostures

	lsm := []byte{}
	lsmPath := "/sys/kernel/security/lsm"

	if _, err := os.Stat(filepath.Clean(lsmPath)); err == nil {
		lsm, err = os.ReadFile(lsmPath)
		if err != nil {
			log.Println(err)
		}
	}

	lsms := string(lsm)

	if cfg.GlobalCfg.Policy && !cfg.GlobalCfg.HostPolicy {
		kd.ContainerSecurity = true
	} else if !cfg.GlobalCfg.Policy && cfg.GlobalCfg.HostPolicy {
		kd.HostSecurity = true
	} else if cfg.GlobalCfg.Policy && cfg.GlobalCfg.HostPolicy {
		kd.ContainerSecurity = true
		kd.HostSecurity = true
	}

	postures.DefaultFilePosture = cfg.GlobalCfg.DefaultFilePosture
	postures.DefaultNetworkPosture = cfg.GlobalCfg.DefaultNetworkPosture
	postures.DefaultCapabilitiesPosture = cfg.GlobalCfg.DefaultCapabilitiesPosture
	postures.HostDefaultFilePosture = cfg.GlobalCfg.HostDefaultFilePosture
	postures.HostDefaultNetworkPosture = cfg.GlobalCfg.HostDefaultNetworkPosture
	postures.HostDefaultCapabilitiesPosture = cfg.GlobalCfg.HostDefaultCapabilitiesPosture

	kd.OSImage = dm.Node.OSImage
	kd.ContainerRuntime = dm.Node.ContainerRuntimeVersion
	kd.KernelVersion = dm.Node.KernelVersion
	kd.KubeletVersion = dm.Node.KubeletVersion
	kd.ContainerRuntime = dm.Node.ContainerRuntimeVersion
	kd.SupportedLSMs = lsms
	kd.KernelHeaderPresent = true //this is always true since kube armor is running
	kd.KubeArmorPosture = postures
	return kd
}

// StrToFile Function
func KarmorDataToFile(val KarmorData, destFile string) {
	j, err := json.Marshal(val)
	if err != nil {
		log.Println(err)
		return
	}
	err = os.WriteFile(destFile, j, 0600)
	if err != nil {
		log.Println(err)
		return
	}

}
