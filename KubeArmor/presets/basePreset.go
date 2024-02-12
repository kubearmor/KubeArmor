package presets

import (
	fd "github.com/kubearmor/KubeArmor/KubeArmor/feeder"
	mon "github.com/kubearmor/KubeArmor/KubeArmor/monitor"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

type BasePreset struct {
	Logger  *fd.Feeder
	Monitor *mon.SystemMonitor
}

type BasePresetInterface interface {
	Name() string
	Init() error
	RegisterPreset(logger *fd.Feeder, monitor *mon.SystemMonitor) (*BasePresetInterface, error)
	RegisterContainer(containerID string, pidns, mntns uint32)
	UnregisterContainer(containerID string)
	UpdateSecurityPolicies(endPoint tp.EndPoint)
	Destroy() error
}
