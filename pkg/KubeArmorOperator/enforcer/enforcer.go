// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package enforcer

import (
	"os"
	"path/filepath"
	"strings"

	probe "github.com/kubearmor/KubeArmor/KubeArmor/utils/bpflsmprobe"
	"go.uber.org/zap"
	"k8s.io/kubectl/pkg/util/slice"
)

// GetAvailableLsms Function
func GetAvailableLsms() []string {
	return []string{"bpf", "selinux", "apparmor"}
}

// CheckBtfSupport checks if BTF is present
func CheckBtfSupport(PathPrefix string, log zap.SugaredLogger) string {
	btfPath := PathPrefix + "/sys/kernel/btf/vmlinux"
	if _, err := os.Stat(filepath.Clean(btfPath)); err == nil {
		return "yes"
	}
	return "no"
}

// CheckIfApparmorFsPresent checks if BTF is present
func CheckIfApparmorFsPresent(PathPrefix string, log zap.SugaredLogger) string {
	path := PathPrefix + "/etc/apparmor.d/tunables"
	if _, err := os.Stat(filepath.Clean(path)); err == nil {
		return "yes"
	}
	return "no"
}

// CheckIfSecurityFsPresent checks if Security filesystem is present
func CheckIfSecurityFsPresent(PathPrefix string, log zap.SugaredLogger) string {
	path := PathPrefix + "/sys/kernel/security"
	if _, err := os.Stat(filepath.Clean(path)); err == nil {
		return "yes"
	}
	return "no"
}

// DetectEnforcer detect the enforcer on the node
func DetectEnforcer(lsmOrder []string, PathPrefix string, log zap.SugaredLogger) string {
	supportedLsms := []string{}
	lsm := []byte{}
	lsmPath := PathPrefix + "/sys/kernel/security/lsm"

	if _, err := os.Stat(filepath.Clean(lsmPath)); err == nil {
		lsm, err = os.ReadFile(lsmPath)
		if err != nil {
			log.Info("Failed to read /sys/kernel/security/lsm " + err.Error())
			goto probeLSM
		}
	}

	supportedLsms = strings.Split(string(lsm), ",")

probeLSM:
	if !slice.ContainsString(supportedLsms, "bpf", nil) {
		err := probe.CheckBPFLSMSupport()
		if err == nil {
			supportedLsms = append(supportedLsms, "bpf")
		} else {
			log.Warnf("BPF LSM not supported %s", err.Error())
		}
	}

	// Check if the AppArmor module is enabled on the system.
	// Refer to Kubernetes documentation for more details:
	// https://kubernetes.io/docs/tutorials/security/apparmor/#before-you-begin
	if !slice.ContainsString(supportedLsms, "apparmor", nil) {
		apparmorModule := PathPrefix + "/sys/module/apparmor/parameters/enabled"
		if _, err := os.Stat(filepath.Clean(apparmorModule)); err == nil {
			data, err := os.ReadFile(apparmorModule)
			if err == nil {
				status := strings.TrimSpace(string(data))
				if status == "Y" {
					supportedLsms = append(supportedLsms, "apparmor")
				} else {
					log.Warn("Apparmor not supported")
				}
			} else {
				log.Info("Failed to read /sys/module/apparmor/parameters/enabled " + err.Error())
			}
		}
	}

	log.Infof("/sys/kernel/security/lsm : %s", string(lsm))
	log.Infof("Supported LSMs %s", strings.Join(supportedLsms, ","))

	return selectLsm(lsmOrder, GetAvailableLsms(), supportedLsms)
}

// selectLsm Function
func selectLsm(lsmOrder, availablelsms, supportedlsm []string) string {
	var lsm string

lsmselection:
	//check lsm preference order
	if len(lsmOrder) != 0 {
		lsm = lsmOrder[0]
		lsmOrder = lsmOrder[1:]
		if slice.ContainsString(supportedlsm, lsm, nil) && slice.ContainsString(availablelsms, lsm, nil) {
			return lsm
		}
		goto lsmselection
	}

	// fallback to available lsms order
	if len(availablelsms) != 0 {
		lsm = availablelsms[0]
		availablelsms = availablelsms[1:]
		if slice.ContainsString(supportedlsm, lsm, nil) {
			return lsm
		}
		goto lsmselection
	}

	return "NA"
}
