//go:build linux

package common

import (
	"strconv"
	"strings"
	"time"

	kg "github.com/kubearmor/KubeArmor/KubeArmor/log"
	"golang.org/x/sys/unix"
)

// get boot time
// credits: https://github.com/kubernetes/kubernetes/blob/master/pkg/kubelet/util/boottime_util_linux.go
func GetBootTime() string {
	currentTime := time.Now()

	var info unix.Sysinfo_t
	if err := unix.Sysinfo(&info); err != nil {
		return ""
	}

	return currentTime.Add(-time.Duration(info.Uptime) * time.Second).Truncate(time.Second).UTC().String()
}

// GetUptimeTimestamp Function
func GetUptimeTimestamp() float64 {
	now := time.Now().UTC()

	res := GetCommandOutputWithoutErr("cat", []string{"/proc/uptime"})

	uptimeDiff := strings.Split(res, " ")[0]

	uptimeDiffSec, err := strconv.ParseInt(strings.Split(uptimeDiff, ".")[0], 10, 64) // second
	if err != nil {
		kg.Err(err.Error())
	}
	uptimeDiffMil, err := strconv.ParseInt(strings.Split(uptimeDiff, ".")[1], 10, 64) // milli second
	if err != nil {
		kg.Err(err.Error())
	}

	uptime := now.Add(-time.Second * time.Duration(uptimeDiffSec))
	uptime = uptime.Add(-time.Millisecond * time.Duration(uptimeDiffMil))

	micro := uptime.UnixNano() / 1000
	up := float64(micro) / 1000000.0

	return up
}
