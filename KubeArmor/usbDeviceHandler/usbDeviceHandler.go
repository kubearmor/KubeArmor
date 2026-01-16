// SPDX-License-Identifier: Apache-2.0
// Copyright 2026  Authors of KubeArmor

package usbdevicehandler

import (
	"bytes"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	fd "github.com/kubearmor/KubeArmor/KubeArmor/feeder"
	mon "github.com/kubearmor/KubeArmor/KubeArmor/monitor"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
	"golang.org/x/sys/unix"
)

// ======================== //
// == USB Device Handler == //
// ======================== //

// EnforcementRule Structure
type EnforcementRule struct {
	Class       int32
	SubClass    int32
	Protocol    int32
	Level       int32
	Action      string
	Specificity int32 // to handle conflicts between class/subclass/protocol
}

// USBDeviceHandler Structure
type USBDeviceHandler struct {
	// logs
	Logger *fd.Feeder

	// rules
	Rules     []EnforcementRule
	RulesLock *sync.RWMutex

	// blocked device list
	BlockedDevices     map[EnforcementRule]string // rule -> sysPath (e.g., "2-4.1:1.0")
	BlockedDevicesLock *sync.RWMutex
}

// NewUSBDeviceHandler Function
func NewUSBDeviceHandler(logger *fd.Feeder) *USBDeviceHandler {
	de := &USBDeviceHandler{}

	de.Logger = logger

	de.Rules = []EnforcementRule{}
	de.RulesLock = &sync.RWMutex{}

	de.BlockedDevices = make(map[EnforcementRule]string)
	de.BlockedDevicesLock = &sync.RWMutex{}

	// handle already connected devices
	de.handleAlreadyConnectedDevies()

	// monitor USB device events
	go de.monitorUSBDeviceEvents()

	return de
}

// monitorUSBDeviceEvents Function
func (de *USBDeviceHandler) monitorUSBDeviceEvents() {
	sock, err := unix.Socket(
		unix.AF_NETLINK,             // domain
		unix.SOCK_DGRAM,             // type, datagram socket
		unix.NETLINK_KOBJECT_UEVENT, // proto/subsystem, listening to kernel uevents
	)
	if err != nil {
		de.Logger.Errf("Error creating socket: %v", err)
		return
	}
	defer unix.Close(sock)

	// Bind to the socket to receive all uevents (pid = 0, groups = 1)
	sa := &unix.SockaddrNetlink{
		Family: unix.AF_NETLINK,
		Groups: 1, // receive broadcast messages (UEVENT group)
	}
	if err := unix.Bind(sock, sa); err != nil {
		de.Logger.Errf("Error binding socket: %v", err)
	}

	de.Logger.Print("Started to monitor USB device events")

	buf := make([]byte, 4096)
	for {
		nr, _, err := unix.Recvfrom(sock, buf, 0)
		if err != nil {
			de.Logger.Errf("Error receiving message: %v", err)
		}

		msg := buf[:nr]
		fields := bytes.Split(msg, []byte{0})

		isUSB := false
		isAdd := false
		isRemove := false

		for _, f := range fields {
			if bytes.HasPrefix(f, []byte("SUBSYSTEM=usb")) {
				isUSB = true
			}
			if bytes.HasPrefix(f, []byte("ACTION=add")) {
				isAdd = true
			}
			if bytes.HasPrefix(f, []byte("ACTION=remove")) {
				isRemove = true
			}
		}

		if isUSB && (isAdd || isRemove) {
			eventData := make(map[string]string)
			for _, f := range fields {
				if len(f) == 0 {
					continue
				}
				pair := strings.SplitN(string(f), "=", 2)
				if len(pair) == 2 {
					eventData[pair[0]] = pair[1]
				}
			}

			devpath := eventData["DEVPATH"]
			base := filepath.Base(devpath) // 2-4.1 or 2-4.1:1.0

			switch eventData["DEVTYPE"] {
			case "usb_device":
				if isAdd {
					de.handleDeviceAdd(filepath.Join("/sys/bus/usb/devices", base), eventData["TYPE"])
				} else if isRemove {
					de.handleDeviceRemove(filepath.Join("/sys/bus/usb/devices", base), eventData["TYPE"])
				}
			case "usb_interface":
				if isAdd {
					de.handleDeviceAdd(filepath.Join("/sys/bus/usb/devices", base), eventData["INTERFACE"])
				} else if isRemove {
					de.handleDeviceRemove(filepath.Join("/sys/bus/usb/devices", base), eventData["INTERFACE"])
				}
			}
		}
	}
}

// handleAlreadyConnectedDevies Function
func (de *USBDeviceHandler) handleAlreadyConnectedDevies() {
	basePath := "/sys/bus/usb/devices"
	entries, err := os.ReadDir(basePath)
	if err != nil {
		de.Logger.Errf("Failed to read directory %s: %v", basePath, err)
		return
	}

	for _, entry := range entries {
		if strings.Contains(entry.Name(), "usb") {
			continue
		}

		devPath := filepath.Join(basePath, entry.Name())

		root, err := os.OpenRoot(devPath)
		if err != nil {
			de.Logger.Errf("Failed to open directory %s: %v", basePath, err)
			return
		}

		descriptors, err := os.ReadDir(devPath)
		if err != nil {
			de.Logger.Errf("Failed to read descriptors of %s: %v", entry.Name(), err)
		}

		var class, subclass, protocol string

		for _, desc := range descriptors {

			readData := func(p string) string {
				file, err := root.Open(p)
				if err != nil {
					return ""
				}
				defer file.Close()

				data, err := io.ReadAll(file)
				if err != nil {
					return ""
				}
				return strings.TrimSpace(string(data))
			}

			if !strings.Contains(entry.Name(), ":") { // device
				switch desc.Name() {
				case "bDeviceClass":
					class = readData("bDeviceClass")
				case "bDeviceSubClass":
					subclass = readData("bDeviceSubClass")
				case "bDeviceProtocol":
					protocol = readData("bDeviceProtocol")
				}
			} else { // interface
				switch desc.Name() {
				case "bInterfaceClass":
					class = readData("bInterfaceClass")
				case "bInterfaceSubClass":
					subclass = readData("bInterfaceSubClass")
				case "bInterfaceProtocol":
					protocol = readData("bInterfaceProtocol")
				}
			}
		}

		if err := root.Close(); err != nil {
			de.Logger.Errf("Failed to close directory %s: %v", devPath, err)
		}

		// Convert from hex string (e.g., "ef") to decimal string (e.g., "239")
		toDec := func(hexStr string) int32 {
			if hexStr == "" {
				return 0
			}
			v, err := strconv.ParseInt(hexStr, 16, 64)
			if err != nil {
				de.Logger.Warnf("Failed to parse hex value %q: %v", hexStr, err)
				return 0
			}
			if v > math.MaxInt32 || v < math.MinInt32 {
				return 0
			}
			return int32(v)
		}

		classDec := toDec(class)
		if classDec == 0 {
			continue
		}

		subclassDec := toDec(subclass)
		protocolDec := toDec(protocol)
		level := int32(getUSBLevel(entry.Name()))

		de.generateLog(EnforcementRule{
			Class: classDec, SubClass: subclassDec, Protocol: protocolDec, Level: level, Action: "Audit (Already Connected)",
		},
			devPath,
		)
	}
}

// getUSBLevel Function
func getUSBLevel(name string) int {
	// Example: "2-4.1" -> 2, "2-4.1.2" -> 3, "2-1" -> 1

	// remove interface/config suffix like ":1.0" if present
	if idx := strings.Index(name, ":"); idx != -1 {
		name = name[:idx]
	}

	// split into bus and path (e.g. ["2", "4.1"])
	parts := strings.SplitN(name, "-", 2)
	if len(parts) < 2 {
		return 0 // invalid format
	}

	// split the path part by "."
	path := parts[1]
	portChain := strings.Split(path, ".")
	return len(portChain)
}

// parseUSBCodes Function
func parseUSBCodes(info string) (class, subclass, protocol int32, err error) {
	parts := strings.Split(info, "/")
	if len(parts) != 3 {
		return 0, 0, 0, fmt.Errorf("invalid format, expected 'class/subclass/protocol'")
	}

	toInt32 := func(s string) (int32, error) {
		v, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return 0, err
		}
		if v > math.MaxInt32 || v < math.MinInt32 {
			return 0, fmt.Errorf("value %d out of int32 range", v)
		}
		return int32(v), nil
	}

	c, err := toInt32(parts[0])
	if err != nil {
		return 0, 0, 0, fmt.Errorf("invalid class: %w", err)
	}
	s, err := toInt32(parts[1])
	if err != nil {
		return 0, 0, 0, fmt.Errorf("invalid subclass: %w", err)
	}
	p, err := toInt32(parts[2])
	if err != nil {
		return 0, 0, 0, fmt.Errorf("invalid protocol: %w", err)
	}

	return c, s, p, nil
}

// handleDeviceAdd Function
func (de *USBDeviceHandler) handleDeviceAdd(sysPath, info string) {
	DeviceDefaultAction := cfg.GlobalCfg.HostDefaultDevicePosture // audit or block

	level := int32(getUSBLevel(filepath.Base(sysPath)))
	class, subclass, protocol, err := parseUSBCodes(info)
	if err != nil {
		de.Logger.Errf("Error: %v", err)
		return
	}

	// if class is 0, return
	if class == 0 {
		return
	}

	de.RulesLock.RLock()
	defer de.RulesLock.RUnlock()

	// Wildcard-aware match
	matches := func(r EnforcementRule) bool {
		if r.Class != -1 && r.Class != class {
			return false
		}
		if r.SubClass != -1 && r.SubClass != subclass {
			return false
		}
		if r.Protocol != -1 && r.Protocol != protocol {
			return false
		}
		if r.Level != -1 && r.Level != level {
			return false
		}
		return true
	}

	hasAnyAllow := false

	for i := range de.Rules {
		r := de.Rules[i]
		if r.Action == "Allow" {
			hasAnyAllow = true
		}

		if !matches(r) {
			continue
		}

		switch r.Action {
		case "Block":
			de.setDeviceAuthorization(r, sysPath, false)
			de.generateLog(
				EnforcementRule{
					Class: class, SubClass: subclass, Protocol: protocol, Level: level, Action: "Block",
				},
				sysPath,
			)
			return
		case "Audit":
			de.generateLog(
				EnforcementRule{
					Class: class, SubClass: subclass, Protocol: protocol, Level: level, Action: "Audit",
				},
				sysPath,
			)
			return
		case "Allow":
			de.generateLog(
				EnforcementRule{
					Class: class, SubClass: subclass, Protocol: protocol, Level: level, Action: "Allow",
				},
				sysPath,
			)
			return
		}
	}

	// there is an explicit allow rule -> default posture
	if hasAnyAllow {
		if strings.ToLower(DeviceDefaultAction) == "block" {
			de.setDeviceAuthorization(
				EnforcementRule{
					Class: class, SubClass: subclass, Protocol: protocol, Level: level, Action: "",
				}, sysPath, false)
			de.generateLog(
				EnforcementRule{
					Class: class, SubClass: subclass, Protocol: protocol, Level: level, Action: "Block",
				},
				sysPath,
			)
			return
		} else if strings.ToLower(DeviceDefaultAction) == "audit" {
			de.generateLog(
				EnforcementRule{
					Class: class, SubClass: subclass, Protocol: protocol, Level: level, Action: "Audit",
				},
				sysPath,
			)
		}
		return
	}

	// host log
	de.generateLog(
		EnforcementRule{
			Class: class, SubClass: subclass, Protocol: protocol, Level: level, Action: "Audit",
		},
		sysPath,
	)

}

// handleDeviceRemove Function
func (de *USBDeviceHandler) handleDeviceRemove(sysPath, info string) {
	level := int32(getUSBLevel(filepath.Base(sysPath)))
	class, subclass, protocol, err := parseUSBCodes(info)
	if err != nil {
		de.Logger.Errf("Error: %v", err)
		return
	}

	// if class is 0, return
	if class == 0 {
		return
	}

	de.generateLog(
		EnforcementRule{
			Class: class, SubClass: subclass, Protocol: protocol, Level: level, Action: "Remove",
		},
		sysPath,
	)
}

// setDeviceAuthorization Function
func (de *USBDeviceHandler) setDeviceAuthorization(rule EnforcementRule, sysPath string, config bool) {

	// Check if sysPath exists (may not exist for an interface if parent device is already deauthorized)
	if _, err := os.Stat(sysPath); os.IsNotExist(err) {
		return
	}

	authPath := filepath.Join(sysPath, "authorized")
	perm := "0"
	if config {
		perm = "1"
	}

	// #nosec G306
	if err := os.WriteFile(authPath, []byte(perm), 0644); err != nil {
		de.Logger.Errf("Failed to write to %s: %v", authPath, err)
	} else {
		if config {
			driverProbePath := "/sys/bus/usb/drivers_probe"
			sysPathBase := filepath.Base(sysPath)
			// manual driver probing
			if err := os.WriteFile(driverProbePath, []byte(sysPathBase), 0200); err != nil {
				de.Logger.Errf("Failed to write to %s: %v", driverProbePath, err)
			} else {
				de.Logger.Debugf("Authorized: %s", filepath.Base(sysPath))
			}
		} else {
			de.Logger.Debugf("Blocked: %s", filepath.Base(sysPath))

			// add this device to BlockedDevices map
			de.BlockedDevices[rule] = sysPath
		}
	}
}

// toUint8Safe Function
func toUint8Safe(v int32) uint8 {
	if v < 0 {
		return 0
	}
	if v > 255 {
		return 255
	}
	return uint8(v)
}

// generateLog Function
func (de *USBDeviceHandler) generateLog(r EnforcementRule, sysPath string) {
	log := tp.Log{}

	log.Operation = "Device"
	log.Resource = mon.GetUSBResource(toUint8Safe(r.Class), toUint8Safe(r.SubClass), toUint8Safe(r.Protocol), toUint8Safe(r.Level))
	log.Data = fmt.Sprintf("Class=%d SubClass=%d Protocol=%d Level=%d SysPath=%s", r.Class, r.SubClass, r.Protocol, r.Level, sysPath)
	log.Action = r.Action
	if r.Action == "Remove" {
		log.Result = "Removed"
	} else if r.Action != "Block" {
		log.Result = "Passed"
	} else {
		log.Result = "Permission denied"
	}
	log.Enforcer = "USBDeviceHandler"

	de.Logger.PushLog(log)
}

// UpdateHostSecurityPolicies Function
func (de *USBDeviceHandler) UpdateHostSecurityPolicies(secPolicies []tp.HostSecurityPolicy) {

	if de == nil {
		return
	}

	hasAllow := false
	newRules := []EnforcementRule{}
	for _, policy := range secPolicies {
		if policy.Spec.Device.MatchDevice != nil {
			for _, dvc := range policy.Spec.Device.MatchDevice {

				if !(strings.EqualFold(dvc.Action, "Audit") || strings.EqualFold(dvc.Action, "Allow") || strings.EqualFold(dvc.Action, "Block")) {
					continue
				}

				r := EnforcementRule{ // -1 is wildcard
					Class:       -1,
					SubClass:    -1,
					Protocol:    -1,
					Level:       -1,
					Action:      "",
					Specificity: 0,
				}

				// class (required): numeric (decimal or 0x…) OR name present in usbClass values
				cs := strings.TrimSpace(dvc.Class)

				// Try numeric parse first (base 0 supports 123 or 0x7B)
				if v, err := strconv.ParseInt(cs, 0, 64); err == nil {
					if v < math.MinInt32 || v > math.MaxInt32 {
						de.Logger.Warnf("Value out of int32 range for class: %s; skipping", cs)
						continue
					}
					r.Class = int32(v)
					if r.Class == 0 {
						de.Logger.Debugf("Class value not supported: %d; skipping", r.Class)
						continue
					}
					r.Specificity += 100
				} else {
					// Reverse-lookup name in usbClass (keep original map)
					upper := strings.ToUpper(cs)
					found := false
					for k, v := range mon.UsbClass {
						if v == upper || upper == "ALL" {
							if v == upper {
								r.Class = int32(k)
							}
							found = true
							r.Specificity += 100
							break
						}
					}
					if !found {
						de.Logger.Warnf("Unknown device class: %s; skipping", cs)
						continue
					}
				}

				if dvc.SubClass != nil {
					r.SubClass = *dvc.SubClass
					r.Specificity += 10
				}
				if dvc.Protocol != nil {
					r.Protocol = *dvc.Protocol
					r.Specificity += 1
				}
				if dvc.Level != nil {
					r.Level = *dvc.Level
					r.Specificity += 100
				}

				if strings.EqualFold(dvc.Action, "Allow") {
					r.Action = "Allow"
					hasAllow = true
				} else if strings.EqualFold(dvc.Action, "Audit") {
					r.Action = "Audit"
				} else {
					r.Action = "Block"
				}

				// priority handling if same rule already exists: Block > Audit > Allow
				replaced := false
				for i, existing := range newRules {
					if existing.Class == r.Class &&
						existing.SubClass == r.SubClass &&
						existing.Protocol == r.Protocol &&
						existing.Level == r.Level {

						// compare action priority
						priority := map[string]int{"Allow": 1, "Audit": 2, "Block": 3}
						if priority[r.Action] > priority[existing.Action] {
							newRules[i] = r // replace lower-priority rule
						}
						replaced = true
						break
					}
				}

				if !replaced {
					newRules = append(newRules, r)
				}
			}
		}
	}

	// Sort rules by specificity (highest first)
	sort.SliceStable(newRules, func(i, j int) bool {
		return newRules[i].Specificity > newRules[j].Specificity
	})

	// update the active rules
	de.RulesLock.Lock()
	defer de.RulesLock.Unlock()
	de.Rules = newRules

	// if there is no allow policy, unblock devices blocked by default block posture if present
	de.BlockedDevicesLock.Lock()
	defer de.BlockedDevicesLock.Unlock()
	if !hasAllow {
		for r, sp := range de.BlockedDevices {
			if r.Action == "" {
				de.setDeviceAuthorization(r, sp, true)
				delete(de.BlockedDevices, r)
			}
		}
	}

	// if block policy is deleted, unblock device
	for rule, sp := range de.BlockedDevices {
		found := false
		for _, r := range de.Rules {
			if r == rule {
				found = true
				break
			}
		}

		if !found {
			// unblock
			de.setDeviceAuthorization(rule, sp, true)
			delete(de.BlockedDevices, rule)
		}
	}
}

// DestroyUSBDeviceHandler Function
func (de *USBDeviceHandler) DestroyUSBDeviceHandler() error {
	// skip if USB device handler is not active
	if de == nil {
		return nil
	}

	// authorize all blocked USB devices
	for r, sp := range de.BlockedDevices {
		de.setDeviceAuthorization(r, sp, true)
		delete(de.BlockedDevices, r)
	}

	// Reset Handler to nil if no errors during clean up
	de = nil
	return nil
}
