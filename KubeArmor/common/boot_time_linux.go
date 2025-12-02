//go:build linux

package common

import (
	"time"

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
