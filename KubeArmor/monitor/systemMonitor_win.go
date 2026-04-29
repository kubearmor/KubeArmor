// //go:build windows

// // SPDX-License-Identifier: Apache-2.0
// // Copyright 2022 Authors of KubeArmor

// // Package monitor is the component responsible for monitoring syscalls and communicating with eBPF Programs
// package monitor

// import (
// 	"bytes"
// 	"encoding/binary"
// 	"fmt"
// 	"strconv"
// 	"sync"
// 	"sync/atomic"
// 	"time"

// 	"syscall"
// 	"unsafe"

// 	"golang.org/x/sys/windows"

// 	fd "github.com/kubearmor/KubeArmor/KubeArmor/feeder"
// 	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
// )

// // SystemMonitor Constant Values
// const (
// 	FilterPort = "\\ScannerPort"

// 	// Buffer sizes
// 	MessageBufferSize = 4096
// 	EventChannelSize  = 1024

// 	// Worker configuration
// 	ReaderGoroutines = 1
// 	WorkerGoroutines = 4

// 	// from fltUser.h
// 	FLT_PORT_FLAG_SYNC_HANDLE = 0x00000001
// )

// var (
// 	fltLib                             = syscall.NewLazyDLL("fltlib.dll")
// 	procFilterConnectCommunicationPort = fltLib.NewProc("FilterConnectCommunicationPort")
// 	procFilterGetMessage               = fltLib.NewProc("FilterGetMessage")
// 	procFilterReplyMessage             = fltLib.NewProc("FilterReplyMessage")
// 	procFilterSendMessage              = fltLib.NewProc("FilterSendMessage")
// )

// type MonitorImpl struct {
// 	*MonitorState
// 	*FilterService
// 	contextChan chan ContextCombined
// }

// // setting-up core module
// func (mon *MonitorImpl) Init() error {
// 	return mon.Start()
// }

// // cleanup monitor resources
// func (mon *MonitorImpl) Destroy() error {
// 	if mon == nil {
// 		return nil
// 	}
// 	return mon.Stop()
// }

// // visibility configuration mgmt
// func (mon *MonitorImpl) UpdateNsVisibility(action string, nsKey NsKey, visibility tp.Visibility) {

// }
// func (mon *MonitorImpl) UpdateDefaultVisibility() {

// }

// // configuration mgmt
// func (mon *MonitorImpl) UpdateConfiguration(key, value uint32) error {
// 	return nil
// }

// // throttling configuration mgmt
// func (mon *MonitorImpl) UpdateThrottlingConfig() {

// }

// // get context channel
// func (mon *MonitorImpl) GetContextChannel() <-chan ContextCombined {
// 	return mon.contextChan
// }

// // start tracing system events
// func (mon *MonitorImpl) TraceEvents() {
// 	// start reader goroutines
// 	for i := 0; i < ReaderGoroutines; i++ {
// 		mon.wg.Add(1)
// 		go mon.readerWorker(i)
// 	}

// 	// start processor goroutines
// 	for i := 0; i < WorkerGoroutines; i++ {
// 		mon.wg.Add(1)
// 		go mon.processorWorker(i)
// 	}

// 	// statistics reporter
// 	mon.wg.Add(1)
// 	go mon.statsReporter()
// }

// func (mon *SystemMonitor) NewMonitor(ms *MonitorState) Monitor {
// 	m := &MonitorImpl{}
// 	m.MonitorState = ms
// 	m.contextChan = make(chan ContextCombined, 4096)
// 	m.FilterService = NewFilterService(nil)
// 	m.FilterService.Logger = ms.Logger
// 	ms.Logger.UpdateEnforcer("Minifilter")
// 	return m
// }

// func (mon *SystemMonitor) NewImaHash(*fd.Feeder, string) ImaHash {
// 	return nil
// }

// // =============================== //
// // == Filter Port Communication == //
// // =============================== //

// // FILTER_MESSAGE_HEADER matches the kernel FILTER_MESSAGE_HEADER structure
// // This is required by the filter manager
// type FILTER_MESSAGE_HEADER struct {
// 	ReplyLength uint32
// 	MessageId   uint64
// }

// // FILTER_REPLY_HEADER for sending replies back to the filter
// type FILTER_REPLY_HEADER struct {
// 	Status    int32  // NTSTATUS value
// 	MessageId uint64 // Must match the MessageId from the received message
// }

// type FilterService struct {
// 	// filter port
// 	portHandle windows.Handle

// 	// channels
// 	eventChan chan []byte
// 	stopCh    chan struct{}

// 	// sync waitgroup
// 	wg sync.WaitGroup

// 	// configurations
// 	maxRetries int
// 	retryDelay time.Duration

// 	// logger
// 	Logger *fd.Feeder

// 	// statistics
// 	messageReceived  atomic.Uint64
// 	messageProcessed atomic.Uint64
// 	messageDropped   atomic.Uint64

// 	running atomic.Bool
// }

// type Config struct {
// 	MaxRetries int
// 	RetryDelay time.Duration
// }

// func defaultConig() *Config {
// 	return &Config{
// 		MaxRetries: 3,
// 		RetryDelay: 1 * time.Second,
// 	}
// }

// func NewFilterService(cfg *Config) *FilterService {
// 	if cfg == nil {
// 		cfg = defaultConig()
// 	}

// 	s := &FilterService{
// 		portHandle: windows.InvalidHandle,
// 		eventChan:  make(chan []byte, EventChannelSize),
// 		stopCh:     make(chan struct{}),
// 		maxRetries: cfg.MaxRetries,
// 		retryDelay: cfg.RetryDelay,
// 	}

// 	return s
// }

// func (s *FilterService) Start() error {
// 	if !s.running.CompareAndSwap(false, true) {
// 		return fmt.Errorf("service already running!")
// 	}

// 	var portHandle windows.Handle
// 	var err error

// 	for i := 0; i < s.maxRetries; i++ {
// 		portHandle, err = s.openFilterPort()
// 		if err == nil {
// 			break
// 		}
// 		s.Logger.Printf("Attempt %d/%d: Failed to open filter port: %v", i+1, s.maxRetries, err)
// 		if i < s.maxRetries-1 {
// 			time.Sleep(s.retryDelay)
// 		}
// 	}

// 	if err != nil {
// 		s.running.Store(false)
// 		return fmt.Errorf("failed to open filter port after %d attempts: %w", s.maxRetries, err)
// 	}
// 	s.portHandle = portHandle

// 	s.Logger.Print("Filter service started!")

// 	return nil
// }

// func (s *FilterService) Stop() error {
// 	if s == nil {
// 		return nil
// 	}
// 	if !s.running.CompareAndSwap(true, false) {
// 		return nil
// 	}

// 	s.Logger.Print("stopping filter service")
// 	close(s.stopCh)

// 	// close port handle
// 	if s.portHandle != windows.InvalidHandle {
// 		windows.CloseHandle(s.portHandle)
// 	}

// 	s.wg.Wait()
// 	close(s.eventChan)

// 	s.Logger.Printf("filter service stopped. Stats - Received: %d Processed: %d Dropped: %d",
// 		s.messageReceived.Load(), s.messageProcessed.Load(), s.messageDropped.Load())

// 	return nil
// }

// func (s *FilterService) openFilterPort() (windows.Handle, error) {
// 	portName, err := windows.UTF16PtrFromString(FilterPort)
// 	if err != nil {
// 		return windows.InvalidHandle, err
// 	}

// 	var handle windows.Handle

// 	// This is calling FilterConnectCommunicationPort - NO CreateFile here!
// 	ret, _, _ := procFilterConnectCommunicationPort.Call(
// 		uintptr(unsafe.Pointer(portName)), // LPCWSTR converted to uintptr
// 		uintptr(0),
// 		uintptr(0),
// 		uintptr(0),
// 		uintptr(0),
// 		uintptr(unsafe.Pointer(&handle)),
// 	)

// 	if ret != 0 {
// 		return windows.InvalidHandle, fmt.Errorf("FilterConnectCommunicationPort failed: 0x%X", ret)
// 	}

// 	return handle, nil
// }

// func (s *FilterService) readerWorker(id int) {
// 	defer s.wg.Done()

// 	s.Logger.Printf("Reader worker %d started", id)
// 	buffer := make([]byte, MessageBufferSize)

// 	for {
// 		select {
// 		case <-s.stopCh:
// 			s.Logger.Printf("Reader worker %d stopped gracefully", id)
// 			return
// 		default:
// 		}
// 		ret, _, lastErr := procFilterGetMessage.Call(
// 			uintptr(s.portHandle),
// 			uintptr(unsafe.Pointer(&buffer[0])),
// 			uintptr(len(buffer)),
// 			uintptr(0), // lpOverlapped (NULL for synchronous op)
// 		)

// 		if ret != 0 {
// 			switch ret {
// 			case uintptr(windows.ERROR_NO_MORE_ITEMS):
// 				s.Logger.Print("Filter port closed (ERROR_NO_MORE_ITEMS)")
// 				return
// 			case uintptr(windows.RPC_S_SERVER_UNAVAILABLE):
// 				s.Logger.Print("Filter driver unavailable (RPC_S_SERVER_UNAVAILABLE)")
// 				return
// 			case uintptr(windows.ERROR_ACCESS_DENIED):
// 				s.Logger.Print("access denied (ERROR_ACCESS_DENIED)")
// 				return
// 			default:
// 				s.Logger.Printf("FilterGetMessage failed with HRESULT: 0x%X, lastErr: %v", ret, lastErr)
// 				return
// 			}
// 		}

// 		select {
// 		case s.eventChan <- buffer:
// 			s.Logger.Printf("buffer data to event channel")
// 			s.messageReceived.Add(1)
// 		default:
// 			s.Logger.Printf("buffer data not ready sleeping for 1 milisec")
// 			time.Sleep(time.Millisecond * 1)
// 			s.messageDropped.Add(1)
// 		}

// 		// _, err := s.parseFilterMessage(buffer)
// 		// if err != nil {
// 		// 	s.Logger.Printf("Reader %d: Parse error (non-fatal): %v", id, err)
// 		// 	continue
// 		// }
// 		// msg, err := s.parseFilterMessage(buffer)
// 		// if err != nil {
// 		// 	s.Logger.Printf("Reader %d: Parse error (non-fatal): %v", id, err)
// 		// 	continue
// 		// }
// 		// s.Logger.Printf("====parsed message====\n%+v", msg)

// 		// msg.UpdatedTime = time.Now().String()

// 		// s.messageReceived.Add(1)

// 		// select {
// 		// case s.eventChan <- msg:
// 		// case <-s.stopCh:
// 		// 	return
// 		// default:
// 		// 	s.messageDropped.Add(1)
// 		// }
// 	}
// }

// func getOperationType(op uint32) string {
// 	switch op {
// 	case 1:
// 		return "Process"
// 	case 2:
// 		return "File"
// 	case 3:
// 		return "Network"
// 	default:
// 		return "INVALID_OPERATION_TYPE"
// 	}
// }

// func getLogType(tp uint32) string {
// 	switch tp {
// 	case 1:
// 		return "HostLog"
// 	case 2:
// 		return "MatchHostPolicy"
// 	default:
// 		return "INVALID_LOG_TYPE"
// 	}
// }

// func getResult(res bool) string {
// 	if res {
// 		return "Passed"
// 	}
// 	return "Permission denied"
// }

// func getAction(blocked bool) string {
// 	if blocked {
// 		return "Block"
// 	}
// 	return "Audit"
// }

// func getFileOperation(op uint32) string {
// 	switch op {
// 	case 0:
// 		return "Create"
// 	case 1:
// 		return "Read"
// 	case 2:
// 		return "Write"
// 	case 3:
// 		return "Delete"
// 	default:
// 		return "INVALID_FILE_OPERATION"
// 	}
// }

// func getVolumeType(volT uint32) string {
// 	switch volT {
// 	default:
// 		return "Unknown"
// 	case 1:
// 		return "Fixed"
// 	case 2:
// 		return "Removable"
// 	case 3:
// 		return "Network"
// 	case 4:
// 		return "RAM"
// 	}
// }

// func handleFileEvent(buf *bytes.Buffer, log_ *tp.Log) {

// 	log_.Type = "HostLog"
// 	log_.Operation = "File"
// 	/*
// 		// operation
// 		var op uint32
// 		err := binary.Read(buf, binary.LittleEndian, &op)
// 		if err != nil {
// 			return
// 		}
// 		// process id
// 		var pid uint32
// 		err = binary.Read(buf, binary.LittleEndian, &pid)
// 		if err != nil {
// 			return
// 		}
// 		// process path offset
// 		var p_path_offset uint32
// 		err = binary.Read(buf, binary.LittleEndian, &p_path_offset)
// 		if err != nil {
// 			return
// 		}
// 		// process path length
// 		var p_path_length uint32
// 		err = binary.Read(buf, binary.LittleEndian, &p_path_length)
// 		if err != nil {
// 			return
// 		}
// 		// file path offset
// 		var f_path_offset uint32
// 		err = binary.Read(buf, binary.LittleEndian, &f_path_offset)
// 		if err != nil {
// 			return
// 		}
// 		// file path length
// 		var f_path_length uint32
// 		err = binary.Read(buf, binary.LittleEndian, &f_path_length)
// 		if err != nil {
// 			return
// 		}

// 		// fmt.Printf("File event:\n Operation: %d, Pid: %d, ProcessPathOffset: %d, ProcessPathLength: %d, FilePathOffset: %d, FilePathLength: %d",
// 		// 	op, pid, p_path_offset, p_path_length, f_path_offset, f_path_length)

// 		// process path string
// 		var p_path_str string
// 		if p_path_length > 0 {
// 			p_path_u16_str := make([]uint16, p_path_length/2)
// 			err = binary.Read(buf, binary.LittleEndian, &p_path_u16_str)
// 			if err != nil {
// 				return
// 			}
// 			p_path_str = windows.UTF16ToString(p_path_u16_str)
// 		}

// 		// file path string
// 		var f_path_str string
// 		if f_path_length > 0 {
// 			f_path_u16_str := make([]uint16, f_path_length/2)
// 			err = binary.Read(buf, binary.LittleEndian, &f_path_u16_str)
// 			if err != nil {
// 				return
// 			}
// 			f_path_str = windows.UTF16ToString(f_path_u16_str)
// 		}

// 		log_.PID = int32(pid)
// 		log_.ProcessName = p_path_str
// 		log_.Resource = f_path_str
// 		log_.Data = getFileOperation(op)
// 	*/

// 	fileEventFields := []uint8{
// 		FieldTimestamp,
// 		FieldProcessID,
// 		FieldFilePath,
// 		FieldVolumeGUID,
// 		FieldVolumeType,
// 		FieldVolumeName,
// 	}

// 	for range fileEventFields {
// 		f, err := parseField(buf)
// 		if err != nil || f == nil {
// 			return
// 		}

// 		switch f.FieldID {
// 		case FieldTimestamp:
// 			log_.Timestamp = int64(f.ULongLong())
// 		case FieldProcessID:
// 			log_.PID = int32(f.ULong())
// 		case FieldFilePath:
// 			log_.Resource = f.UnicodeString()
// 		case FieldVolumeGUID:
// 			// log_.Data += "volumeGUID=" + string(f.Binary()) + " "
// 		case FieldVolumeType:
// 			log_.Data += "volumeType=" + getVolumeType(f.ULong()) + " "
// 		case FieldVolumeName:
// 			log_.Data += "volumeName=" + f.UnicodeString() + " "
// 		default:
// 			continue
// 		}
// 	}

// 	// fmt.Printf("log :\n%+v", log_)

// }

// func handleProcessEvent(buf *bytes.Buffer, log_ *tp.Log) {

// 	log_.Type = "HostLog"
// 	log_.Operation = "Process"

// 	processEventFields := []uint8{
// 		FieldTimestamp,
// 		FieldProcessID,
// 		FieldParentProcessID,
// 		FieldParentProcessImagePath,
// 		FieldCreatorProcessID,
// 		FieldCreatorProcessImagePath,
// 		FieldImagePath,
// 		FieldCommandLine,
// 		FieldExitCode,
// 	}

// 	for range processEventFields {
// 		f, err := parseField(buf)
// 		if err != nil || f == nil { // parsing error or end of data
// 			return
// 		}

// 		switch f.FieldID {
// 		case FieldTimestamp:
// 			log_.Timestamp = int64(f.ULongLong())
// 			fmt.Printf("parsed process timestamp: %v\n", log_.Timestamp)
// 		case FieldProcessID:
// 			log_.PID = int32(f.ULong())
// 			fmt.Printf("parsed process id: %v\n", log_.PID)
// 		case FieldParentProcessID:
// 			log_.PPID = int32(f.ULong())
// 			fmt.Printf("parsed parent process id: %v\n", log_.PPID)
// 		case FieldParentProcessImagePath:
// 			log_.ParentProcessName = f.UnicodeString()
// 			fmt.Printf("parsed parent process imagePath: %v\n", log_.ParentProcessName)
// 		case FieldCreatorProcessID:
// 			log_.HostPPID = int32(f.ULong())
// 			fmt.Printf("parsed creator process id: %v\n", log_.HostPPID)
// 		case FieldCreatorProcessImagePath:
// 			fmt.Printf("parsed creator process imagePath: %v\n", f.UnicodeString())
// 		case FieldImagePath:
// 			log_.ProcessName = f.UnicodeString()
// 			fmt.Printf("parsed process imagepath: %v\n", log_.ProcessName)
// 		case FieldCommandLine:
// 			log_.Source = f.UnicodeString()
// 			fmt.Printf("parsed process commandline: %v\n", log_.Source)
// 		case FieldExitCode:
// 			log_.Result = strconv.Itoa(int(f.ULong()))
// 			fmt.Printf("parsed process exit code: %v\n", log_.Result)
// 		default:
// 			fmt.Printf("unknown process field: %v\n", f.FieldID)
// 			continue
// 		}
// 	}

// }

// func (s *FilterService) parseFilterMessage(buf []byte) (*tp.Log, error) {

// 	headerSize := 32 + 64

// 	if len(buf) < headerSize {
// 		return nil, fmt.Errorf("invalid message, header too short")
// 	}

// 	dataBuf := bytes.NewBuffer(buf)

// 	// read header
// 	var header FILTER_MESSAGE_HEADER
// 	// header->replyLength
// 	var replyLength uint32
// 	err := binary.Read(dataBuf, binary.LittleEndian, &replyLength)
// 	if err != nil {
// 		return nil, err
// 	}

// 	// padding bits
// 	var padding uint32
// 	err = binary.Read(dataBuf, binary.LittleEndian, &padding)
// 	if err != nil {
// 		return nil, err
// 	}

// 	// header->messageId
// 	var messageId uint64
// 	err = binary.Read(dataBuf, binary.LittleEndian, &messageId)
// 	if err != nil {
// 		return nil, err
// 	}

// 	header.ReplyLength = replyLength
// 	header.MessageId = messageId

// 	// s.Logger.Printf("header: %+v", header)

// 	// parse event type
// 	// eType, err := parseField(dataBuf)
// 	// if err != nil {
// 	// 	return nil, err
// 	// }

// 	// remainingData := len(buf) - headerSize

// 	// rawBytes, err := readByteSliceFromBuff(dataBuf, remainingData)

// 	// if err != nil {
// 	// 	s.Logger.Printf("error reading the buffer data: %v", err)
// 	// 	return nil, fmt.Errorf("error reading the buffer data")
// 	// }

// 	// s.Logger.Printf("received event: ", hex.Dump(rawBytes))

// 	// return nil, fmt.Errorf("debugging raw data")

// 	eType, err := parseEventType(dataBuf)
// 	if err != nil {
// 		s.Logger.Warnf("error parsing event type: %s", err)
// 		return nil, err
// 	}

// 	s.Logger.Printf("event type header: %+v", eType)
// 	if eType.FieldID != FieldEventType {
// 		s.Logger.Warnf("first data element is not event type: %d", eType.FieldID)
// 		return nil, fmt.Errorf("data is misalligned")
// 	}

// 	log_ := &tp.Log{}

// 	switch eType.Type { // eType.ULong()
// 	case EventTypeFileCreate,
// 		EventTypeFileRead,
// 		EventTypeFileWrite,
// 		EventTypeFileSetInfo,
// 		EventTypeFileRename,
// 		EventTypeFileDelete,
// 		EventTypeFileCLOSE:
// 		// s.Logger.Printf("file event received")
// 		handleFileEvent(dataBuf, log_)
// 	case EventTypeProcessCreate,
// 		EventTypeProcessTerminate:
// 		s.Logger.Printf("process event received")
// 		handleProcessEvent(dataBuf, log_)
// 		log_.Data += " Event=" + getProcessEvent(eType.Type)
// 	default:
// 		s.Logger.Warnf("unsupported event type: %d", eType.Type) //eType.ULong())
// 	}

// 	return log_, nil

// 	// timestamp uint64
// 	var ts uint64
// 	err = binary.Read(dataBuf, binary.LittleEndian, &ts)
// 	if err != nil {
// 		return nil, err
// 	}
// 	// type uint32
// 	var tp_ uint32
// 	err = binary.Read(dataBuf, binary.LittleEndian, &tp_)
// 	if err != nil {
// 		return nil, err
// 	}
// 	// operation uint32
// 	var op uint32
// 	err = binary.Read(dataBuf, binary.LittleEndian, &op)
// 	if err != nil {
// 		return nil, err
// 	}
// 	// result
// 	var blocked bool
// 	err = binary.Read(dataBuf, binary.LittleEndian, &blocked)
// 	if err != nil {
// 		return nil, err
// 	}

// 	action := ""
// 	if tp_ == 2 {
// 		action = getAction(blocked)
// 	}

// 	log_ = &tp.Log{
// 		Timestamp: int64(ts),
// 		Type:      getLogType(tp_),
// 		Operation: getOperationType(op),
// 		Result:    getResult(blocked),
// 		Action:    action,
// 	}

// 	switch op {
// 	case 1:
// 		// handle process operation
// 	case 2:
// 		// handle file operation
// 		handleFileEvent(dataBuf, log_)
// 	case 3:
// 		// handle network operation
// 	default:
// 		s.Logger.Printf("Invalid operation type")
// 	}

// 	return log_, nil
// }

// func (s *FilterService) processorWorker(id int) {
// 	defer s.wg.Done()

// 	s.Logger.Printf("Processor worker %d started", id)

// 	var localProcessed uint64

// 	lastStatsLog := time.Now()

// 	for {
// 		select {
// 		case <-s.stopCh:
// 			s.Logger.Printf("Processor worker %d stopped (processed: %d)", id, localProcessed)
// 			return
// 		case msg, ok := <-s.eventChan:
// 			if !ok {
// 				s.Logger.Printf("Processor worker %d event channel closed", id)
// 				return
// 			}

// 			parsedMsg, err := s.parseFilterMessage(msg)
// 			if err != nil {
// 				s.Logger.Warnf("failed to parse filter message: %s", err)
// 				continue
// 			}

// 			err = s.processMessage(parsedMsg)
// 			s.Logger.Print("processed message")
// 			if err == nil {
// 				localProcessed++
// 			}

// 			if time.Since(lastStatsLog) > 30*time.Second {
// 				s.Logger.Printf("Worker %d stats: processed=%d", id, localProcessed)
// 				lastStatsLog = time.Now()
// 			}

// 		default:
// 			s.Logger.Print("processor sleeping for a sec")
// 			time.Sleep(time.Second * 1)
// 		}

// 	}
// }

// func (s *FilterService) processMessage(msg *tp.Log) error {
// 	s.Logger.Printf("received message to process: %+v", msg)
// 	if msg == nil {
// 		return nil
// 	}
// 	switch msg.Type {
// 	case "HostLog":
// 		s.Logger.Print("sent log to feeder")
// 		s.Logger.PushLog(*msg)
// 	default:
// 		s.Logger.Print("invalid log type")
// 	}

// 	return nil
// }

// func (s *FilterService) statsReporter() {
// 	defer s.wg.Done()

// 	ticker := time.NewTicker(10 * time.Second)
// 	defer ticker.Stop()

// 	for {
// 		select {
// 		case <-s.stopCh:
// 			return
// 		case <-ticker.C:

// 			s.Logger.Printf("====Stats====\n%v", s.GetServiceStats())
// 		}
// 	}
// }

// func (s *FilterService) GetServiceStats() map[string]interface{} {
// 	pending := uint64(len(s.eventChan))

// 	return map[string]interface{}{
// 		"received":  s.messageReceived.Load(),
// 		"processed": s.messageProcessed.Load(),
// 		"pending":   pending,
// 		"dropped":   s.messageDropped.Load(),
// 	}

// }

//go:build windows

// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package monitor

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
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
		windows.CloseHandle(s.portHandle)
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
			uintptr(s.portHandle),
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
	case EventTypeFileCreate,
		EventTypeFileRead,
		EventTypeFileWrite,
		EventTypeFileSetInfo,
		EventTypeFileRename,
		EventTypeFileDelete,
		EventTypeFileCLOSE:

		select {
		case s.fileEventChan <- evt:
			s.fileReceived.Add(1)
		default:
			s.fileDropped.Add(1)
			s.Logger.Warnf("file event channel full — dropped event type %d", evt.eType.Type)
		}

	case EventTypeProcessCreate,
		EventTypeProcessTerminate:

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
			handleFileEvent(bytes.NewBuffer(evt.buf), log_)
			log_.Data += " Event=" + getFileEvent(evt.eType.Type)
			log_.Data = strings.TrimSpace(log_.Data)
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
			handleProcessEvent(bytes.NewBuffer(evt.buf), log_)
			log_.Data += " Event=" + getProcessEvent(evt.eType.Type)
			log_.Data = strings.TrimSpace(log_.Data)
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
	buf := bytes.NewBuffer(payload)
	eType, err = parseEventType(buf)
	if err != nil {
		return nil, nil, err
	}
	if eType.FieldID != FieldEventType {
		return nil, nil, fmt.Errorf("first field is not FieldEventType (got %d)", eType.FieldID)
	}
	// buf.Bytes() is the unconsumed tail after parseEventType.
	remaining = buf.Bytes()
	return
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
		return "MatchHostPolicy"
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

func handleFileEvent(buf *bytes.Buffer, log_ *tp.Log) {
	log_.Type = "HostLog"
	log_.Operation = "File"

	fileEventFields := []uint8{
		FieldTimestamp,
		FieldProcessID,
		FieldImagePath,
		FieldFilePath,
		FieldVolumeGUID,
		FieldVolumeType,
		FieldVolumeName,
	}

	for i, _ := range fileEventFields {
		f, err := parseField(buf)
		if err != nil || f == nil {
			if err != nil {
				fmt.Printf("failed to parse file event after %d fields: %v, remaining bytes: %d\n",
					i+1, err, buf.Len())
			} else {
				fmt.Println("reached end of the event")
			}
			return
		}
		switch f.FieldID {
		case FieldTimestamp:
			log_.Timestamp = int64(f.ULongLong())
		case FieldProcessID:
			fmt.Println("parsing FieldProcessID")
			log_.PID = int32(f.ULong())
		case FieldImagePath:
			log_.ProcessName = f.UnicodeString()
		case FieldFilePath:
			log_.Resource = f.UnicodeString()
		case FieldVolumeType:
			fmt.Println("parsing FieldVolumeType")
			log_.Data += "volumeType=" + getVolumeType(f.ULong()) + " "
		case FieldVolumeName:
			log_.Data += "volumeName=" + f.UnicodeString() + " "
		}
	}
}

func handleProcessEvent(buf *bytes.Buffer, log_ *tp.Log) {
	log_.Type = "HostLog"
	log_.Operation = "Process"

	processEventFields := []uint8{
		FieldTimestamp,
		FieldProcessID,
		FieldParentProcessID,
		FieldParentProcessImagePath,
		FieldCreatorProcessID,
		FieldCreatorProcessImagePath,
		FieldImagePath,
		FieldCommandLine,
		FieldExitCode,
		FieldProcessUserSID,
		FieldProcessTokenElevation,
		FieldProcessTokenElevationType,
	}

	for i, _ := range processEventFields {
		f, err := parseField(buf)
		if err != nil || f == nil {
			if err != nil {
				fmt.Printf("failed to parse process event after %d fields: %v, remaining bytes: %d\n",
					i+1, err, buf.Len())
			} else {
				fmt.Println("reached end of the event")
			}
			return
		}
		switch f.FieldID {
		case FieldTimestamp:
			log_.Timestamp = int64(f.ULongLong())
		case FieldProcessID:
			fmt.Println("parsing FieldProcessID")
			log_.PID = int32(f.ULong())
		case FieldParentProcessID:
			fmt.Println("parsing FieldParentProcessID")
			log_.PPID = int32(f.ULong())
		case FieldParentProcessImagePath:
			log_.ParentProcessName = f.UnicodeString()
		case FieldCreatorProcessID:
			fmt.Println("parsing FieldCreatorProcessID")
			log_.HostPPID = int32(f.ULong())
		case FieldImagePath:
			log_.ProcessName = f.UnicodeString()
		case FieldCommandLine:
			log_.Source = f.UnicodeString()
		case FieldExitCode:
			fmt.Println("parsing FieldExitCode")
			log_.Result = strconv.Itoa(int(f.ULong()))
		case FieldProcessUserSID:
			log_.Data = log_.Data + " UserSid=" + f.UnicodeString()
		case FieldProcessTokenElevation:
			log_.Data = log_.Data + " Elevated=" + strconv.FormatBool(f.Boolean())
		case FieldProcessTokenElevationType:
			fmt.Println("parsing FieldProcessTokenElevationType")
			log_.Data = log_.Data + " ElevationType=" + getElevationType(f.ULong())
		}
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
