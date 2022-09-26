package runtime

import (
	"os"

	"github.com/kubearmor/KubeArmor/pkg/KubeArmorOperator/common"
	"go.uber.org/zap"
)

func DetectRuntimeViaMap(pathPrefix string, log zap.SugaredLogger) (string, string) {
	for runtime, paths := range common.ContainerRuntimeSocketMap {
		for _, path := range paths {
			if _, err := os.Stat(pathPrefix + path); err == nil {
				return runtime, path
			}
		}
	}
	log.Warn("Could'nt detect runtime")
	return "NA", "NA"
}

func DetectRuntimeStorage(pathPrefix, runtime string, log zap.SugaredLogger) string {

	for _, storagelocaltion := range common.RuntimeStorageVolumes[runtime] {
		if _, err := os.Stat(pathPrefix + storagelocaltion); err == nil {
			return storagelocaltion
		}
	}
	return "NA"
}
