//go:build windows
// +build windows

// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package enforcer

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	fd "github.com/kubearmor/KubeArmor/KubeArmor/feeder"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
	"golang.org/x/sys/windows"
)

// AppLocker block Event IDs in "Microsoft-Windows-AppLocker/EXE and DLL":
//   8002 = EXE allowed in audit mode (would have been blocked)
//   8003 = EXE allowed in enforce mode (allowed by rule)  -- NOT a block
//   8004 = EXE BLOCKED in enforce mode  ← the one we want
// In "Microsoft-Windows-AppLocker/MSI and Script":
//   8007 = Script blocked
// In "Microsoft-Windows-AppLocker/Packaged app-Execution":
//   8022 = Packaged app blocked
//
// AppLocker 8004 EventData XML has Named Data items:
//   <Data Name='PolicyName'>EXE</Data>
//   <Data Name='RuleName'>KubeArmor Block Notepad.exe</Data>
//   <Data Name='TargetProcessId'>8740</Data>
//   <Data Name='FilePath'>C:\...\Notepad.exe</Data>
//   ...
//
// System section uses attributes for ProcessID:
//   <Execution ProcessID='5144' ThreadID='4260'/>
//   <EventRecordID>22</EventRecordID>

const (
	// AppLocker log channels
	appLockerExeDllChannel       = "Microsoft-Windows-AppLocker/EXE and DLL"
	appLockerMsiScriptChannel    = "Microsoft-Windows-AppLocker/MSI and Script"
	appLockerPackagedChannel     = "Microsoft-Windows-AppLocker/Packaged app-Execution"

	evtQueryChannelPath = uintptr(0x1)
)

var (
	winevtDLL = syscall.NewLazyDLL("wevtapi.dll")
	evtQuery  = winevtDLL.NewProc("EvtQuery")
	evtNext   = winevtDLL.NewProc("EvtNext")
	evtClose  = winevtDLL.NewProc("EvtClose")
	evtRender = winevtDLL.NewProc("EvtRender")
)

// AppLockerPoller reads AppLocker block events from the Windows Event Log
// and pushes them as MatchedHostPolicy alerts through the KubeArmor feeder.
type AppLockerPoller struct {
	logger   *fd.Feeder
	stopCh   chan struct{}
	wg       sync.WaitGroup
	interval time.Duration
	// Per-channel record ID cursors to avoid re-processing events
	lastRecordID map[string]uint64
}

// NewAppLockerPoller creates a poller but does not start it.
func NewAppLockerPoller(logger *fd.Feeder) *AppLockerPoller {
	return &AppLockerPoller{
		logger:   logger,
		stopCh:   make(chan struct{}),
		interval: 5 * time.Second,
		lastRecordID: map[string]uint64{
			appLockerExeDllChannel:    0,
			appLockerMsiScriptChannel: 0,
			appLockerPackagedChannel:  0,
		},
	}
}

// Start checks AppLocker readiness, then seeds cursors and begins polling.
func (p *AppLockerPoller) Start() {
	p.checkAndEnsureAppLockerReady()

	// Seed cursors so we only emit NEW events, not historical ones.
	for ch := range p.lastRecordID {
		events, _ := p.queryChannel(ch, 0)
		for _, ev := range events {
			if ev.recordID > p.lastRecordID[ch] {
				p.lastRecordID[ch] = ev.recordID
			}
		}
	}
	p.wg.Add(1)
	go p.run()
}

// checkAndEnsureAppLockerReady inspects the current state of the AppID service
// and all three AppLocker event log channels. It logs what it finds and only
// enables a channel if it is currently disabled — it never blindly overrides.
func (p *AppLockerPoller) checkAndEnsureAppLockerReady() {
	// --- 1. Check AppID service ---
	if running, err := isServiceRunning("AppIDSvc"); err != nil {
		p.logger.Warnf("AppLocker: cannot query AppIDSvc state: %v", err)
	} else if running {
		p.logger.Printf("AppLocker: AppIDSvc is running ✓")
	} else {
		p.logger.Warnf("AppLocker: AppIDSvc is NOT running — " +
			"start it with: Start-Service AppIDSvc")
	}

	// --- 2. Check and conditionally enable each log channel ---
	channels := []string{
		appLockerExeDllChannel,
		appLockerMsiScriptChannel,
		appLockerPackagedChannel,
	}
	for _, ch := range channels {
		enabled, err := isEventChannelEnabled(ch)
		if err != nil {
			// Channel may not exist on this Windows SKU — skip silently.
			p.logger.Debugf("AppLocker: cannot query channel %q: %v", ch, err)
			continue
		}
		if enabled {
			p.logger.Printf("AppLocker: event channel %q is enabled ✓", ch)
		} else {
			p.logger.Warnf("AppLocker: event channel %q is DISABLED — enabling it now", ch)
			if err := enableEventChannel(ch); err != nil {
				p.logger.Warnf("AppLocker: failed to enable %q: %v "+
					"(run: wevtutil sl %q /e:true)", ch, err, ch)
			} else {
				p.logger.Printf("AppLocker: event channel %q enabled ✓", ch)
			}
		}
	}
}

// isServiceRunning returns true if the named Windows service is in the
// SERVICE_RUNNING state. Uses the Service Control Manager via the Windows API.
func isServiceRunning(name string) (bool, error) {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return false, fmt.Errorf("OpenSCManager: %w", err)
	}
	defer windows.CloseServiceHandle(scm)

	svcName, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return false, err
	}
	svc, err := windows.OpenService(scm, svcName, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return false, fmt.Errorf("OpenService(%s): %w", name, err)
	}
	defer windows.CloseServiceHandle(svc)

	var status windows.SERVICE_STATUS
	if err := windows.QueryServiceStatus(svc, &status); err != nil {
		return false, fmt.Errorf("QueryServiceStatus(%s): %w", name, err)
	}
	return status.CurrentState == windows.SERVICE_RUNNING, nil
}

// isEventChannelEnabled queries wevtutil via EvtGetChannelConfigProperty to
// check whether the named channel has logging enabled, without parsing any
// command output.
func isEventChannelEnabled(channel string) (bool, error) {
	// We use wevtutil via exec since the EVT channel-config APIs require
	// a lot of boilerplate for a single boolean. The output is stable.
	out, err := runPowershell(
		fmt.Sprintf(`(Get-WinEvent -ListLog '%s' -ErrorAction SilentlyContinue).IsEnabled`, channel))
	if err != nil {
		return false, err
	}
	v := strings.TrimSpace(strings.ToLower(out))
	if v == "true" {
		return true, nil
	}
	if v == "false" {
		return false, nil
	}
	// Empty output = channel doesn't exist on this SKU
	return false, fmt.Errorf("channel not found")
}

// enableEventChannel enables an AppLocker event log channel using wevtutil.
func enableEventChannel(channel string) error {
	_, err := runPowershell(
		fmt.Sprintf(`wevtutil sl '%s' /e:true`, channel))
	return err
}

// runPowershell runs a single PowerShell expression and returns its stdout.
func runPowershell(expr string) (string, error) {
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", expr)
	out, err := cmd.Output()
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			return "", fmt.Errorf("powershell error: %s", string(exitError.Stderr))
		}
		return "", err
	}
	return string(out), nil
}

// Stop signals the poller to stop and waits for it to exit.
func (p *AppLockerPoller) Stop() {
	close(p.stopCh)
	p.wg.Wait()
}

func (p *AppLockerPoller) run() {
	defer p.wg.Done()
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	for {
		select {
		case <-p.stopCh:
			return
		case <-ticker.C:
			p.poll()
		}
	}
}

func (p *AppLockerPoller) poll() {
	for ch := range p.lastRecordID {
		events, err := p.queryChannel(ch, p.lastRecordID[ch])
		if err != nil {
			p.logger.Debugf("AppLocker poller [%s]: %v", ch, err)
			continue
		}
		for _, ev := range events {
			p.pushAlert(ev, ch)
			if ev.recordID > p.lastRecordID[ch] {
				p.lastRecordID[ch] = ev.recordID
			}
		}
	}
}

// appLockerEvent holds the fields we extract from a block event.
type appLockerEvent struct {
	recordID    uint64
	processPath string // FilePath data item
	ruleName    string // RuleName data item
	pid         uint32 // TargetProcessId data item
	eventID     uint16
}

func blockEventXPath(channel string, afterRecordID uint64) string {
	// Block event IDs differ per channel:
	//   EXE and DLL:          8004
	//   MSI and Script:       8007 (8008 is SKU not supported)
	//   Packaged app-Exec:    8022
	var ids string
	switch channel {
	case appLockerMsiScriptChannel:
		ids = "EventID=8007"
	case appLockerPackagedChannel:
		// 8022 = specific app blocked, 8027 = ALL apps blocked (due to missing rules)
		ids = "(EventID=8022 or EventID=8027)"
	default: // appLockerExeDllChannel
		ids = "EventID=8004"
	}

	if afterRecordID == 0 {
		return fmt.Sprintf("*[System[%s]]", ids)
	}
	return fmt.Sprintf("*[System[%s and EventRecordID > %d]]", ids, afterRecordID)
}

func (p *AppLockerPoller) queryChannel(channel string, afterRecordID uint64) ([]appLockerEvent, error) {
	xpath := blockEventXPath(channel, afterRecordID)

	channelPtr, err := windows.UTF16PtrFromString(channel)
	if err != nil {
		return nil, err
	}
	xpathPtr, err := windows.UTF16PtrFromString(xpath)
	if err != nil {
		return nil, err
	}

	hQuery, _, lastErr := evtQuery.Call(
		0,
		uintptr(unsafe.Pointer(channelPtr)),
		uintptr(unsafe.Pointer(xpathPtr)),
		evtQueryChannelPath,
	)
	if hQuery == 0 {
		// Channel may not exist on this SKU — not an error worth logging loudly.
		return nil, fmt.Errorf("EvtQuery(%s): %w", channel, lastErr)
	}
	defer evtClose.Call(hQuery) //nolint:errcheck

	var results []appLockerEvent
	handles := make([]uintptr, 16)
	for {
		var returned uint32
		ret, _, _ := evtNext.Call(
			hQuery,
			uintptr(len(handles)),
			uintptr(unsafe.Pointer(&handles[0])),
			0, 0,
			uintptr(unsafe.Pointer(&returned)),
		)
		if ret == 0 || returned == 0 {
			break
		}
		for i := uint32(0); i < returned; i++ {
			ev, err := parseAppLockerBlockEvent(handles[i])
			if err == nil {
				results = append(results, ev)
			}
			evtClose.Call(handles[i]) //nolint:errcheck
		}
	}
	return results, nil
}

const evtRenderEventXml = uintptr(1)

// parseAppLockerBlockEvent renders the event as XML and extracts fields.
// AppLocker 8004 XML structure (relevant parts):
//
//	<System>
//	  <EventID>8004</EventID>
//	  <EventRecordID>123</EventRecordID>
//	  <Execution ProcessID='5144' ThreadID='4260'/>
//	</System>
//	<EventData>
//	  <Data Name='PolicyName'>EXE</Data>
//	  <Data Name='RuleName'>KubeArmor Block Notepad.exe</Data>
//	  <Data Name='TargetProcessId'>8740</Data>
//	  <Data Name='FilePath'>C:\...\Notepad.exe</Data>
//	  ...
//	</EventData>
func parseAppLockerBlockEvent(handle uintptr) (appLockerEvent, error) {
	ev := appLockerEvent{}

	bufSize := uint32(32768)
	buf := make([]uint16, bufSize)
	var used, propCount uint32

	ret, _, lastErr := evtRender.Call(
		0,
		handle,
		evtRenderEventXml,
		uintptr(bufSize*2),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&used)),
		uintptr(unsafe.Pointer(&propCount)),
	)
	if ret == 0 {
		return ev, fmt.Errorf("EvtRender: %w", lastErr)
	}

	xml := windows.UTF16ToString(buf)

	// Extract system fields using simple tag parsing
	ev.recordID = parseSimpleTag(xml, "EventRecordID")
	ev.eventID = uint16(parseSimpleTag(xml, "EventID"))

	// Event 8027 has no EventData (it's a blanket block), so use generic defaults
	if ev.eventID == 8027 {
		ev.processPath = "Unknown_Packaged_App"
		ev.ruleName = "Default_Deny_All_Packaged_Apps"
		// pid cannot be determined reliably from 8027
		return ev, nil
	}

	// Extract EventData fields. AppLocker uses two different XML schemas:
	//   - EXE/DLL/Script channels: plain child elements inside <UserData>
	//       e.g. <FilePath>C:\Windows\notepad.exe</FilePath>
	//   - Some channels use <Data Name='FilePath'>value</Data> format
	// Try both, preferring the named-data format.
	parseField := func(name string) string {
		if v := parseNamedData(xml, name); v != "" {
			return v
		}
		return parseSimpleTagStr(xml, name)
	}

	ev.processPath = parseField("FilePath")
	ev.ruleName = parseField("RuleName")
	pid := parseField("TargetProcessId")
	if pid != "" {
		var n uint32
		fmt.Sscanf(pid, "%d", &n)
		ev.pid = n
	}

	return ev, nil
}

// pushAlert emits a tp.Log routed as a MatchedHostPolicy alert.
func (p *AppLockerPoller) pushAlert(ev appLockerEvent, channel string) {
	timestamp, updatedTime := kl.GetDateTimeNow()

	processName := ev.processPath
	policyName := "AppLocker-Process-Block"
	if ev.ruleName != "" {
		policyName = ev.ruleName
	}

	log := tp.Log{
		Timestamp:   timestamp,
		UpdatedTime: updatedTime,

		// "MatchedHostPolicy" is the exact string feeder.PushLog checks to
		// route to pb.Alert (the gRPC alert channel).
		Type:       "MatchedHostPolicy",
		Operation:  "Process",
		Action:     "Block",
		Result:     "Permission denied",
		PolicyName: policyName,
		Enforcer:   "AppLocker",
		Severity:   "5",
		Message: fmt.Sprintf("AppLocker blocked process (EventID %d, channel: %s)",
			ev.eventID, channel),

		ProcessName: processName,
		Resource:    processName,
		Source:      filepath.Base(processName),
		PID:         int32(ev.pid),
	}

	p.logger.PushLog(log)
	p.logger.Printf("AppLocker alert: blocked %q PID=%d EventID=%d",
		processName, ev.pid, ev.eventID)
}

// ── XML parsing helpers ────────────────────────────────────────────────────

// parseSimpleTag extracts the text content of a plain XML tag, e.g.
//   <EventRecordID>22</EventRecordID> → 22
func parseSimpleTagStr(xml, tag string) string {
	open := "<" + tag + ">"
	close := "</" + tag + ">"
	s := strings.Index(xml, open)
	if s == -1 {
		return ""
	}
	s += len(open)
	e := strings.Index(xml[s:], close)
	if e == -1 {
		return ""
	}
	return xml[s : s+e]
}

func parseSimpleTag(xml, tag string) uint64 {
	v := parseSimpleTagStr(xml, tag)
	if v == "" {
		return 0
	}
	var n uint64
	fmt.Sscanf(strings.TrimSpace(v), "%d", &n)
	return n
}

// parseNamedData extracts the value of an AppLocker <Data Name='key'>value</Data> item.
// This handles both single-quote and double-quote attribute variants.
func parseNamedData(xml, name string) string {
	// Try single-quote form first (most common in rendered XML)
	for _, attr := range []string{
		"<Data Name='" + name + "'>",
		`<Data Name="` + name + `">`,
	} {
		s := strings.Index(xml, attr)
		if s == -1 {
			continue
		}
		s += len(attr)
		e := strings.Index(xml[s:], "</Data>")
		if e == -1 {
			continue
		}
		return xml[s : s+e]
	}
	return ""
}