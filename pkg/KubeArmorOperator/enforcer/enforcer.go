package enforcer

import (
	"os"
	"path/filepath"
	"strings"

	"go.uber.org/zap"
	"k8s.io/kubectl/pkg/util/slice"
)

// GetAvailableLsms Functio
func GetAvailableLsms() []string {
	return []string{"bpf", "selinux", "apparmor"}
}

// DetectEnforcer: detect the enforcer on the node
func DetectEnforcer(lsmOrder []string, PathPrefix string, log zap.SugaredLogger) string {
	lsm := []byte{}
	lsmPath := PathPrefix + "/sys/kernel/security/lsm"

	if _, err := os.Stat(filepath.Clean(lsmPath)); err == nil {
		lsm, err = os.ReadFile(lsmPath)
		if err != nil {
			log.Info("Failed to read /sys/kernel/security/lsm " + err.Error())
			return "NA"
		}
	}

	enforcer := string(lsm)

	return selectLsm(lsmOrder, GetAvailableLsms(), strings.Split(enforcer, ","))
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
