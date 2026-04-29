//go:build windows

package common

func GetBootTime() string {
	// TODO: get boot time in windows
	return ""
}

// GetUptimeTimestamp Function
func GetUptimeTimestamp() float64 {

	return float64(0)
}
