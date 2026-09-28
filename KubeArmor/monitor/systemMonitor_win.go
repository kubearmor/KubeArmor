//go:build windows

// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package monitor

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	fd "github.com/kubearmor/KubeArmor/KubeArmor/feeder"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

// SystemMonitor Constant Values
const (
	FilterPort = "\\ScannerPort"

	// Buffer sizes
	MessageBufferSize = 4096

	// Channel capacities — tune independently per event volume
	FileEventChannelSize    = 2048
	ProcessEventChannelSize = 512

	// Worker counts — file events are higher volume, process events are lower
	ReaderGoroutines        = 1
	FileWorkerGoroutines    = 4
	ProcessWorkerGoroutines = 2

	// from fltUser.h
	FLT_PORT_FLAG_SYNC_HANDLE = 0x00000001
)

var (
	fltLib                             = syscall.NewLazyDLL("fltlib.dll")
	procFilterConnectCommunicationPort = fltLib.NewProc("FilterConnectCommunicationPort")
	procFilterGetMessage               = fltLib.NewProc("FilterGetMessage")
	procFilterReplyMessage             = fltLib.NewProc("FilterReplyMessage")
	procFilterSendMessage              = fltLib.NewProc("FilterSendMessage")
)

// rawEvent carries a parsed event type tag alongside the original buffer so
// routing is done once (in the reader) and each worker pool only sees its
// own event type — no further type-switching needed in the hot path.
type rawEvent struct {
	eType *EventType // already parsed from the header
	buf   []byte     // remaining payload bytes after the event-type field
	msgID uint64
}

type FilterService struct {
	portHandle windows.Handle

	// Separate channels give each event class independent back-pressure,
	// independent depths, and dedicated worker pools with no head-of-line
	// blocking between file and process events.
	fileEventChan    chan rawEvent
	processEventChan chan rawEvent

	stopCh chan struct{}
	wg     sync.WaitGroup

	maxRetries int
	retryDelay time.Duration

	Logger *fd.Feeder

	// Per-type counters for fine-grained observability.
	fileReceived  atomic.Uint64
	fileProcessed atomic.Uint64
	fileDropped   atomic.Uint64
	procReceived  atomic.Uint64
	procProcessed atomic.Uint64
	procDropped   atomic.Uint64

	running atomic.Bool
}

type Config struct {
	MaxRetries int
	RetryDelay time.Duration
}

func defaultConfig() *Config {
	return &Config{
		MaxRetries: 3,
		RetryDelay: 1 * time.Second,
	}
}

func NewFilterService(cfg *Config) *FilterService {
	if cfg == nil {
		cfg = defaultConfig()
	}
	return &FilterService{
		portHandle:       windows.InvalidHandle,
		fileEventChan:    make(chan rawEvent, FileEventChannelSize),
		processEventChan: make(chan rawEvent, ProcessEventChannelSize),
		stopCh:           make(chan struct{}),
		maxRetries:       cfg.MaxRetries,
		retryDelay:       cfg.RetryDelay,
	}
}

// ------------------------------------------------------------------ lifecycle

func (s *FilterService) Start() error {
	if !s.running.CompareAndSwap(false, true) {
		return fmt.Errorf("service already running")
	}

	portHandle, err := s.connectWithRetry()
	if err != nil {
		s.running.Store(false)
		return err
	}
	s.portHandle = portHandle
	s.Logger.Print("Filter service started")
	return nil
}

func (s *FilterService) Stop() error {
	if s == nil {
		return nil
	}
	if !s.running.CompareAndSwap(true, false) {
		return nil
	}

	s.Logger.Print("Stopping filter service")
	close(s.stopCh)

	if s.portHandle != windows.InvalidHandle {
		// CancelIoEx unblocks any FilterGetMessage call that is currently
		// blocked in the kernel waiting for the next event. Without this,
		// the readerWorker goroutine never wakes up (it only checks stopCh
		// before the blocking call, not during it), so s.wg.Wait() below
		// blocks indefinitely — causing the service to hang in STOP_PENDING.
		//
		// Passing nil as the second argument cancels ALL pending I/O on the
		// handle. The readerWorker will return with ERROR_OPERATION_ABORTED.
		if err := windows.CancelIoEx(s.portHandle, nil); err != nil {
			// CancelIoEx can legitimately fail if no I/O is pending (e.g.
			// the worker hasn't called FilterGetMessage yet). That's fine.
			if err != windows.ERROR_NOT_FOUND {
				s.Logger.Warnf("CancelIoEx on filter port: %v", err)
			}
		}
		windows.CloseHandle(s.portHandle)
		s.portHandle = windows.InvalidHandle
	}

	s.wg.Wait()
	close(s.fileEventChan)
	close(s.processEventChan)

	s.Logger.Printf(
		"Filter service stopped — file(recv=%d proc=%d drop=%d) process(recv=%d proc=%d drop=%d)",
		s.fileReceived.Load(), s.fileProcessed.Load(), s.fileDropped.Load(),
		s.procReceived.Load(), s.procProcessed.Load(), s.procDropped.Load(),
	)
	return nil
}

func (s *FilterService) connectWithRetry() (windows.Handle, error) {
	var (
		handle windows.Handle
		err    error
	)
	for i := 0; i < s.maxRetries; i++ {
		handle, err = s.openFilterPort()
		if err == nil {
			return handle, nil
		}
		s.Logger.Printf("Attempt %d/%d: failed to open filter port: %v", i+1, s.maxRetries, err)
		if i < s.maxRetries-1 {
			time.Sleep(s.retryDelay)
		}
	}
	return windows.InvalidHandle, fmt.Errorf("failed to open filter port after %d attempts: %w", s.maxRetries, err)
}

func (s *FilterService) openFilterPort() (windows.Handle, error) {
	portName, err := windows.UTF16PtrFromString(FilterPort)
	if err != nil {
		return windows.InvalidHandle, err
	}
	var handle windows.Handle
	ret, _, _ := procFilterConnectCommunicationPort.Call(
		uintptr(unsafe.Pointer(portName)),
		uintptr(0), uintptr(0), uintptr(0), uintptr(0),
		uintptr(unsafe.Pointer(&handle)),
	)
	if ret != 0 {
		return windows.InvalidHandle, fmt.Errorf("FilterConnectCommunicationPort failed: 0x%X", ret)
	}
	return handle, nil
}

// --------------------------------------------------------------- TraceEvents

// TraceEvents launches all goroutines. Call once after Start().
func (s *FilterService) TraceEvents() {
	for i := 0; i < ReaderGoroutines; i++ {
		s.wg.Add(1)
		go s.readerWorker(i)
	}
	for i := 0; i < FileWorkerGoroutines; i++ {
		s.wg.Add(1)
		go s.fileProcessorWorker(i)
	}
	for i := 0; i < ProcessWorkerGoroutines; i++ {
		s.wg.Add(1)
		go s.processProcessorWorker(i)
	}
	s.wg.Add(1)
	go s.statsReporter()
}

// ---------------------------------------------------------------- readerWorker
//
// Responsibilities (only):
//   1. Read raw bytes from the kernel via FilterGetMessage.
//   2. Strip the FILTER_MESSAGE_HEADER.
//   3. Parse the leading EventType field to determine routing.
//   4. Copy the remaining payload into a rawEvent and send to the
//      correct typed channel — NO further parsing here.

func (s *FilterService) readerWorker(id int) {
	defer s.wg.Done()
	s.Logger.Printf("Reader worker %d started", id)

	// Take a local snapshot of portHandle. Stop() may close and invalidate
	// the field concurrently; we hold our own copy so that the FilterGetMessage
	// call uses a stable value, and CancelIoEx in Stop() unblocks us cleanly.
	handle := s.portHandle

	buf := make([]byte, MessageBufferSize)

	for {
		// Check stop before blocking in FilterGetMessage.
		select {
		case <-s.stopCh:
			s.Logger.Printf("Reader worker %d stopped", id)
			return
		default:
		}

		clear(buf)

		ret, _, lastErr := procFilterGetMessage.Call(
			uintptr(handle),
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(len(buf)),
			uintptr(0),
		)
		if ret != 0 {
			s.handleGetMessageError(ret, lastErr)
			return
		}

		msgID, payload, err := stripFilterHeader(buf)
		if err != nil {
			s.Logger.Warnf("Reader %d: bad header: %v", id, err)
			continue
		}

		eType, remaining, err := parseLeadingEventType(payload)
		if err != nil {
			s.Logger.Warnf("Reader %d: cannot parse event type: %v", id, err)
			continue
		}

		// Make an independent copy of the payload so the next read can reuse buf.
		payloadCopy := make([]byte, len(remaining))
		copy(payloadCopy, remaining)

		evt := rawEvent{eType: eType, buf: payloadCopy, msgID: msgID}
		s.route(evt)
	}
}

// route sends the event to the appropriate typed channel without blocking the
// reader.  Drops are counted per type so we can alert on process-event loss
// separately from (much noisier) file-event loss.
func (s *FilterService) route(evt rawEvent) {

	switch evt.eType.Type {
	case 2: // File
		select {
		case s.fileEventChan <- evt:
			s.fileReceived.Add(1)
		default:
			s.fileDropped.Add(1)
			s.Logger.Warnf("file event channel full — dropped event type %d", evt.eType.Type)
		}

	case 1: // Process
		select {
		case s.processEventChan <- evt:
			s.procReceived.Add(1)
		default:
			s.procDropped.Add(1)
			s.Logger.Warnf("process event channel full — dropped event type %d", evt.eType.Type)
		}

	default:
		s.Logger.Warnf("unsupported event type %d — discarded", evt.eType.Type)
	}
}

func (s *FilterService) handleGetMessageError(ret uintptr, lastErr error) {
	switch ret {
	case uintptr(windows.ERROR_NO_MORE_ITEMS):
		s.Logger.Print("Filter port closed (ERROR_NO_MORE_ITEMS)")
	case uintptr(windows.RPC_S_SERVER_UNAVAILABLE):
		s.Logger.Print("Filter driver unavailable (RPC_S_SERVER_UNAVAILABLE)")
	case uintptr(windows.ERROR_ACCESS_DENIED):
		s.Logger.Print("Access denied (ERROR_ACCESS_DENIED)")
	case uintptr(windows.ERROR_OPERATION_ABORTED):
		// Normal shutdown path: Stop() called CancelIoEx which unblocked us.
		s.Logger.Print("Filter port I/O cancelled — reader exiting cleanly")
	case uintptr(windows.ERROR_INVALID_HANDLE):
		// Handle was closed by Stop() before/during FilterGetMessage — clean exit.
		s.Logger.Print("Filter port handle closed — reader exiting cleanly")
	default:
		s.Logger.Printf("FilterGetMessage failed HRESULT=0x%X lastErr=%v", ret, lastErr)
	}
}

// --------------------------------------------------------- fileProcessorWorker
//
// Blocks on fileEventChan only. Never touches processEventChan.
// A slow file-parse cannot starve process events.

func (s *FilterService) fileProcessorWorker(id int) {
	defer s.wg.Done()
	s.Logger.Printf("File processor worker %d started", id)

	for {
		select {
		case <-s.stopCh:
			s.Logger.Printf("File processor worker %d stopped", id)
			return
		case evt, ok := <-s.fileEventChan:
			if !ok {
				return
			}
			log_ := &tp.Log{}
			handleFileEvent(evt.buf, log_)
			if err := s.processMessage(log_); err == nil {
				s.fileProcessed.Add(1)
			}
		}
	}
}

// ------------------------------------------------------ processProcessorWorker
//
// Blocks on processEventChan only. Never touches fileEventChan.

func (s *FilterService) processProcessorWorker(id int) {
	defer s.wg.Done()
	s.Logger.Printf("Process processor worker %d started", id)

	for {
		select {
		case <-s.stopCh:
			s.Logger.Printf("Process processor worker %d stopped", id)
			return
		case evt, ok := <-s.processEventChan:
			if !ok {
				return
			}
			log_ := &tp.Log{}
			handleProcessEvent(evt.buf, log_)
			if err := s.processMessage(log_); err == nil {
				s.procProcessed.Add(1)
			}
		}
	}
}

// ---------------------------------------------------------------- processMessage

func (s *FilterService) processMessage(msg *tp.Log) error {
	if msg == nil {
		return nil
	}
	switch msg.Type {
	case "HostLog":
		s.Logger.PushLog(*msg)
	case "MatchedHostPolicy":
		// Blocked event — route as an alert via the feeder pipeline
		s.Logger.PushLog(*msg)
	default:
		s.Logger.Warnf("unknown log type: %q", msg.Type)
	}
	return nil
}

// ---------------------------------------------------------------- statsReporter

func (s *FilterService) statsReporter() {
	defer s.wg.Done()
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.Logger.Printf("====Stats====\n%v", s.GetServiceStats())
		}
	}
}

func (s *FilterService) GetServiceStats() map[string]interface{} {
	return map[string]interface{}{
		"file_received":     s.fileReceived.Load(),
		"file_processed":    s.fileProcessed.Load(),
		"file_pending":      uint64(len(s.fileEventChan)),
		"file_dropped":      s.fileDropped.Load(),
		"process_received":  s.procReceived.Load(),
		"process_processed": s.procProcessed.Load(),
		"process_pending":   uint64(len(s.processEventChan)),
		"process_dropped":   s.procDropped.Load(),
	}
}

// ----------------------------------------------------------- header / parsing helpers

const filterMessageHeaderSize = 16 // 4 (ReplyLength) + 4 (padding) + 8 (MessageId)

// stripFilterHeader reads the FILTER_MESSAGE_HEADER and returns the message ID
// plus the remaining payload bytes.
func stripFilterHeader(buf []byte) (msgID uint64, payload []byte, err error) {
	if len(buf) < filterMessageHeaderSize {
		return 0, nil, fmt.Errorf("buffer too short (%d bytes)", len(buf))
	}
	r := bytes.NewReader(buf)

	var replyLength uint32
	if err = binary.Read(r, binary.LittleEndian, &replyLength); err != nil {
		return
	}
	var padding uint32
	if err = binary.Read(r, binary.LittleEndian, &padding); err != nil {
		return
	}
	if err = binary.Read(r, binary.LittleEndian, &msgID); err != nil {
		return
	}
	payload = buf[filterMessageHeaderSize:]
	return
}

// parseLeadingEventType reads the EventType field from the front of payload
// and returns it together with the remaining bytes (so callers do not need to
// re-create a buffer).
func parseLeadingEventType(payload []byte) (eType *EventType, remaining []byte, err error) {
	if len(payload) < 16 {
		return nil, nil, fmt.Errorf("payload too short")
	}
	op := binary.LittleEndian.Uint32(payload[12:16])
	eType = &EventType{
		Type: op,
	}
	return eType, payload, nil
}

func getOperationType(op uint32) string {
	switch op {
	case 1:
		return "Process"
	case 2:
		return "File"
	case 3:
		return "Network"
	default:
		return "INVALID_OPERATION_TYPE"
	}
}

func getLogType(tp uint32) string {
	switch tp {
	case 1:
		return "HostLog"
	case 2:
		// Must match feeder.PushLog routing: "MatchedHostPolicy" → Alert
		return "MatchedHostPolicy"
	default:
		return "INVALID_LOG_TYPE"
	}
}

func getResult(res bool) string {
	if res {
		return "Passed"
	}
	return "Permission denied"
}

func getAction(blocked bool) string {
	if blocked {
		return "Block"
	}
	return "Audit"
}

func getFileOperation(op uint32) string {
	switch op {
	case 0:
		return "Create"
	case 1:
		return "Read"
	case 2:
		return "Write"
	case 3:
		return "Delete"
	case 4:
		return "Rename"
	case 5:
		return "SetInfo"
	case 7:
		return "Close"
	default:
		return "INVALID_FILE_OPERATION"
	}
}

func getVolumeType(volT uint32) string {
	switch volT {
	case 1:
		return "Fixed"
	case 2:
		return "Removable"
	case 3:
		return "Network"
	case 4:
		return "RAM"
	default:
		return "Unknown"
	}
}

func getElevationType(et uint32) string {
	switch et {
	case 1:
		return "Default"
	case 2:
		return "Full"
	case 3:
		return "Limited"
	default:
		return "Unknown"
	}
}

func handleFileEvent(buf []byte, log_ *tp.Log) {
	if len(buf) < 53 {
		return
	}
	log_.Operation = "File"
	log_.Timestamp = int64(binary.LittleEndian.Uint64(buf[0:8]))

	// Read event type from EVENT struct (offset 8, FS_EVENT_TYPE enum)
	// 1 = EventType_HostLog, 2 = EventType_MatchHostPolicy
	evType := binary.LittleEndian.Uint32(buf[8:12])
	log_.Type = getLogType(evType)

	// Read blocked flag from EVENT struct (offset 16, BOOLEAN)
	blocked := buf[16] != 0
	log_.Action = getAction(blocked)
	log_.Result = getResult(!blocked)

	if blocked {
		log_.Type = "MatchedHostPolicy"
	}

	log_.Enforcer = "Minifilter"

	fileOp := binary.LittleEndian.Uint32(buf[17:21])
	log_.PID = int32(binary.LittleEndian.Uint32(buf[21:25]))
	log_.PPID = int32(binary.LittleEndian.Uint32(buf[25:29]))

	pPathOff := binary.LittleEndian.Uint32(buf[29:33])
	pPathLen := binary.LittleEndian.Uint32(buf[33:37])
	fPathOff := binary.LittleEndian.Uint32(buf[37:41])
	fPathLen := binary.LittleEndian.Uint32(buf[41:45])
	ppPathOff := binary.LittleEndian.Uint32(buf[45:49])
	ppPathLen := binary.LittleEndian.Uint32(buf[49:53])

	if pPathOff > 0 && pPathLen > 0 && int(pPathOff+pPathLen) <= len(buf) {
		pPathBytes := buf[pPathOff : pPathOff+pPathLen]
		u16Str := make([]uint16, pPathLen/2)
		for i := range u16Str {
			u16Str[i] = binary.LittleEndian.Uint16(pPathBytes[i*2:])
		}
		log_.ProcessName = windows.UTF16ToString(u16Str)
		log_.Source = log_.ProcessName
	}

	if log_.ProcessName == "" && log_.PID > 0 {
		// Fallback: look up process name from PID if driver failed to provide it
		handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(log_.PID))
		if err == nil {
			defer windows.CloseHandle(handle)
			pathBuf := make([]uint16, windows.MAX_PATH)
			size := uint32(len(pathBuf))
			err = windows.QueryFullProcessImageName(handle, 0, &pathBuf[0], &size)
			if err == nil {
				log_.ProcessName = windows.UTF16ToString(pathBuf[:size])
				log_.Source = log_.ProcessName
			}
		}
	}

	if fPathOff > 0 && fPathLen > 0 && int(fPathOff+fPathLen) <= len(buf) {
		fPathBytes := buf[fPathOff : fPathOff+fPathLen]
		u16Str := make([]uint16, fPathLen/2)
		for i := range u16Str {
			u16Str[i] = binary.LittleEndian.Uint16(fPathBytes[i*2:])
		}
		log_.Resource = windows.UTF16ToString(u16Str)
	}

	if ppPathOff > 0 && ppPathLen > 0 && int(ppPathOff+ppPathLen) <= len(buf) {
		ppPathBytes := buf[ppPathOff : ppPathOff+ppPathLen]
		u16Str := make([]uint16, ppPathLen/2)
		for i := range u16Str {
			u16Str[i] = binary.LittleEndian.Uint16(ppPathBytes[i*2:])
		}
		log_.ParentProcessName = windows.UTF16ToString(u16Str)
	}

	if log_.ParentProcessName == "" && log_.PPID > 0 {
		// Fallback: look up parent process name from PPID if driver failed to provide it
		handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(log_.PPID))
		if err == nil {
			defer windows.CloseHandle(handle)
			pathBuf := make([]uint16, windows.MAX_PATH)
			size := uint32(len(pathBuf))
			err = windows.QueryFullProcessImageName(handle, 0, &pathBuf[0], &size)
			if err == nil {
				log_.ParentProcessName = windows.UTF16ToString(pathBuf[:size])
			}
		}
	}

	// Resolve the correct policy name from the registry using the resource path.
	// This replaces the old hardcoded "KubeArmor-File-Block".
	if evType == 2 || blocked {
		if log_.Resource != "" {
			if name := GetPolicyNameRegistry().Lookup(log_.Resource); name != "" {
				log_.PolicyName = name
			} else {
				log_.PolicyName = "KubeArmor-File-Block"
			}
		} else {
			log_.PolicyName = "KubeArmor-File-Block"
		}
	}

	log_.Data = "Event=" + getFileOperation(fileOp)
}

func handleProcessEvent(buf []byte, log_ *tp.Log) {
	if len(buf) < 53 {
		return
	}

	// Parse EVENT header (packed layout, from EventStructs.h):
	//   buf[0:8]   = timestamp (ULONGLONG)
	//   buf[8:12]  = type (FS_EVENT_TYPE: 1=HostLog, 2=MatchHostPolicy)
	//   buf[12:16] = operation (FS_EVENT_OPERATION: 1=Process)
	//   buf[16]    = blocked (BOOLEAN)
	//   buf[17+]   = PROCESS_EVENT union
	log_.Timestamp = int64(binary.LittleEndian.Uint64(buf[0:8]))
	evType := binary.LittleEndian.Uint32(buf[8:12])
	// buf[12:16] is operation — always Process here, skip
	blocked := buf[16] != 0

	log_.Operation = "Process"
	log_.Enforcer = "Minifilter"

	procOp := binary.LittleEndian.Uint32(buf[17:21])
	log_.PID = int32(binary.LittleEndian.Uint32(buf[21:25]))
	log_.PPID = int32(binary.LittleEndian.Uint32(buf[25:29]))

	pPathOff := binary.LittleEndian.Uint32(buf[29:33])
	pPathLen := binary.LittleEndian.Uint32(buf[33:37])
	cmdOff := binary.LittleEndian.Uint32(buf[37:41])
	cmdLen := binary.LittleEndian.Uint32(buf[41:45])
	ppPathOff := binary.LittleEndian.Uint32(buf[45:49])
	ppPathLen := binary.LittleEndian.Uint32(buf[49:53])

	if pPathOff > 0 && pPathLen > 0 && int(pPathOff+pPathLen) <= len(buf) {
		pPathBytes := buf[pPathOff : pPathOff+pPathLen]
		u16Str := make([]uint16, pPathLen/2)
		for i := range u16Str {
			u16Str[i] = binary.LittleEndian.Uint16(pPathBytes[i*2:])
		}
		log_.ProcessName = windows.UTF16ToString(u16Str)
		log_.Resource = log_.ProcessName
	}

	if log_.ProcessName == "" && log_.PID > 0 {
		handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(log_.PID))
		if err == nil {
			defer windows.CloseHandle(handle)
			pathBuf := make([]uint16, windows.MAX_PATH)
			size := uint32(len(pathBuf))
			err = windows.QueryFullProcessImageName(handle, 0, &pathBuf[0], &size)
			if err == nil {
				log_.ProcessName = windows.UTF16ToString(pathBuf[:size])
				log_.Resource = log_.ProcessName
			}
		}
	}

	if cmdOff > 0 && cmdLen > 0 && int(cmdOff+cmdLen) <= len(buf) {
		cmdBytes := buf[cmdOff : cmdOff+cmdLen]
		u16Str := make([]uint16, cmdLen/2)
		for i := range u16Str {
			u16Str[i] = binary.LittleEndian.Uint16(cmdBytes[i*2:])
		}
		log_.Source = windows.UTF16ToString(u16Str)
	}

	if ppPathOff > 0 && ppPathLen > 0 && int(ppPathOff+ppPathLen) <= len(buf) {
		ppPathBytes := buf[ppPathOff : ppPathOff+ppPathLen]
		u16Str := make([]uint16, ppPathLen/2)
		for i := range u16Str {
			u16Str[i] = binary.LittleEndian.Uint16(ppPathBytes[i*2:])
		}
		log_.ParentProcessName = windows.UTF16ToString(u16Str)
	}

	if procOp == 0 {
		log_.Data = "Event=Create"
	} else {
		log_.Data = "Event=Terminate"
	}

	// Route as a policy-match alert when the driver matched a rule (evType==2),
	// distinguishing Block (enforcement) from Audit (telemetry-only).
	if evType == 2 {
		// Both Block and Audit rule matches surface as MatchedHostPolicy.
		// The Action and Result fields distinguish them.
		log_.Type = "MatchedHostPolicy"
		log_.Action = getAction(blocked)
		log_.Result = getResult(!blocked)
		// Resolve policy name from the registry using the process image path.
		if log_.Resource != "" {
			if name := GetPolicyNameRegistry().Lookup(log_.Resource); name != "" {
				log_.PolicyName = name
			} else {
				log_.PolicyName = "KubeArmor-Process-Block"
			}
		} else {
			log_.PolicyName = "KubeArmor-Process-Block"
		}
	} else {
		log_.Type = "HostLog"
		log_.Action = "Audit"
		log_.Result = "Passed"
	}
}

type MonitorImpl struct {
	*MonitorState
	*FilterService
	contextChan chan ContextCombined
}

func (mon *MonitorImpl) Init() error                                           { return mon.Start() }
func (mon *MonitorImpl) Destroy() error                                        { return mon.Stop() }
func (mon *MonitorImpl) UpdateNsVisibility(_ string, _ NsKey, _ tp.Visibility) {}
func (mon *MonitorImpl) UpdateDefaultVisibility()                              {}
func (mon *MonitorImpl) UpdateConfiguration(_, _ uint32) error                 { return nil }
func (mon *MonitorImpl) UpdateThrottlingConfig()                               {}
func (mon *MonitorImpl) GetContextChannel() <-chan ContextCombined             { return mon.contextChan }

func (mon *MonitorImpl) TraceEvents() {
	mon.FilterService.TraceEvents()
}

func (mon *SystemMonitor) NewMonitor(ms *MonitorState) Monitor {
	m := &MonitorImpl{}
	m.MonitorState = ms
	m.contextChan = make(chan ContextCombined, 4096)
	m.FilterService = NewFilterService(nil)
	m.FilterService.Logger = ms.Logger
	ms.Logger.UpdateEnforcer("Minifilter")
	return m
}

func (mon *SystemMonitor) NewImaHash(*fd.Feeder, string) ImaHash { return nil }
func (mon *MonitorImpl) InitImaHash() error                      { return nil }
func (mon *MonitorImpl) DestroyImaHash() error                   { return nil }
func (mon *MonitorImpl) UpdateMatchArgsConfig()                  {}
