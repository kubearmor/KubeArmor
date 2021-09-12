// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package feeder

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	kg "github.com/kubearmor/KubeArmor/KubeArmor/log"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"

	"github.com/google/uuid"
	pb "github.com/kubearmor/KubeArmor/protobuf"
	"google.golang.org/grpc"
)

// ============ //
// == Global == //
// ============ //

// Running flag
var Running bool

// MsgQueue for Messages
var MsgQueue chan pb.Message

// AlertQueue for alerts
var AlertQueue chan pb.Alert

// LogQueue for Logs
var LogQueue chan pb.Log

func init() {
	Running = true

	MsgQueue = make(chan pb.Message, 1024)
	AlertQueue = make(chan pb.Alert, 4096)
	LogQueue = make(chan pb.Log, 32768)
}

// ========== //
// == gRPC == //
// ========== //

// MsgStruct Structure
type MsgStruct struct {
	Client pb.LogService_WatchMessagesServer
	Filter string
}

// AlertStruct Structure
type AlertStruct struct {
	Client pb.LogService_WatchAlertsServer
	Filter string
}

// LogStruct Structure
type LogStruct struct {
	Client pb.LogService_WatchLogsServer
	Filter string
}

// LogService Structure
type LogService struct {
	MsgStructs map[string]MsgStruct
	MsgLock    *sync.Mutex

	AlertStructs map[string]AlertStruct
	AlertLock    *sync.Mutex

	LogStructs map[string]LogStruct
	LogLock    *sync.Mutex
}

// HealthCheck Function
func (ls *LogService) HealthCheck(ctx context.Context, nonce *pb.NonceMessage) (*pb.ReplyMessage, error) {
	replyMessage := pb.ReplyMessage{Retval: nonce.Nonce}
	return &replyMessage, nil
}

// addMsgStruct Function
func (ls *LogService) addMsgStruct(uid string, srv pb.LogService_WatchMessagesServer, filter string) {
	ls.MsgLock.Lock()
	defer ls.MsgLock.Unlock()

	msgStruct := MsgStruct{}
	msgStruct.Client = srv
	msgStruct.Filter = filter

	ls.MsgStructs[uid] = msgStruct
}

// removeMsgStruct Function
func (ls *LogService) removeMsgStruct(uid string) {
	ls.MsgLock.Lock()
	defer ls.MsgLock.Unlock()

	delete(ls.MsgStructs, uid)
}

// getMsgStructs Function
func (ls *LogService) getMsgStructs() []MsgStruct {
	msgStructs := []MsgStruct{}

	ls.MsgLock.Lock()
	defer ls.MsgLock.Unlock()

	for _, mgs := range ls.MsgStructs {
		msgStructs = append(msgStructs, mgs)
	}

	return msgStructs
}

// WatchMessages Function
func (ls *LogService) WatchMessages(req *pb.RequestMessage, svr pb.LogService_WatchMessagesServer) error {
	uid := uuid.Must(uuid.NewRandom()).String()

	ls.addMsgStruct(uid, svr, req.Filter)
	defer ls.removeMsgStruct(uid)

	for Running {
		//nolint
		msg := <-MsgQueue

		msgStructs := ls.getMsgStructs()
		for _, mgs := range msgStructs {
			if err := mgs.Client.Send(&msg); err != nil {
				kg.Err("Failed to send a message")
			}
		}
	}

	return nil
}

// addAlertStruct Function
func (ls *LogService) addAlertStruct(uid string, srv pb.LogService_WatchAlertsServer, filter string) {
	ls.AlertLock.Lock()
	defer ls.AlertLock.Unlock()

	alertStruct := AlertStruct{}
	alertStruct.Client = srv
	alertStruct.Filter = filter

	ls.AlertStructs[uid] = alertStruct
}

// removeAlertStruct Function
func (ls *LogService) removeAlertStruct(uid string) {
	ls.AlertLock.Lock()
	defer ls.AlertLock.Unlock()

	delete(ls.AlertStructs, uid)
}

// getAlertStructs Function
func (ls *LogService) getAlertStructs() []AlertStruct {
	alertStructs := []AlertStruct{}

	ls.AlertLock.Lock()
	defer ls.AlertLock.Unlock()

	for _, als := range ls.AlertStructs {
		alertStructs = append(alertStructs, als)
	}

	return alertStructs
}

// WatchAlerts Function
func (ls *LogService) WatchAlerts(req *pb.RequestMessage, svr pb.LogService_WatchAlertsServer) error {
	uid := uuid.Must(uuid.NewRandom()).String()

	ls.addAlertStruct(uid, svr, req.Filter)
	defer ls.removeAlertStruct(uid)

	for Running {
		//nolint
		alert := <-AlertQueue

		alertStructs := ls.getAlertStructs()
		for _, als := range alertStructs {
			if err := als.Client.Send(&alert); err != nil {
				kg.Err("Failed to send an alert")
			}
		}
	}

	return nil
}

// addLogStruct Function
func (ls *LogService) addLogStruct(uid string, srv pb.LogService_WatchLogsServer, filter string) {
	ls.LogLock.Lock()
	defer ls.LogLock.Unlock()

	logStruct := LogStruct{}
	logStruct.Client = srv
	logStruct.Filter = filter

	ls.LogStructs[uid] = logStruct
}

// removeLogStruct Function
func (ls *LogService) removeLogStruct(uid string) {
	ls.LogLock.Lock()
	defer ls.LogLock.Unlock()

	delete(ls.LogStructs, uid)
}

// getLogStructs Function
func (ls *LogService) getLogStructs() []LogStruct {
	logStructs := []LogStruct{}

	ls.LogLock.Lock()
	defer ls.LogLock.Unlock()

	for _, lgs := range ls.LogStructs {
		logStructs = append(logStructs, lgs)
	}

	return logStructs
}

// WatchLogs Function
func (ls *LogService) WatchLogs(req *pb.RequestMessage, svr pb.LogService_WatchLogsServer) error {
	uid := uuid.Must(uuid.NewRandom()).String()

	ls.addLogStruct(uid, svr, req.Filter)
	defer ls.removeLogStruct(uid)

	for Running {
		//nolint
		log := <-LogQueue

		logStructs := ls.getLogStructs()
		for _, lgs := range logStructs {
			if err := lgs.Client.Send(&log); err != nil {
				kg.Err("Failed to send a log")
			}
		}
	}

	return nil
}

// ============ //
// == Feeder == //
// ============ //

// Feeder Structure
type Feeder struct {
	// port
	Port string

	// output
	Output  string
	Filter  string
	LogFile *os.File

	// gRPC listener
	Listener net.Listener

	// log server
	LogServer *grpc.Server

	// wait group
	WgServer sync.WaitGroup

	// cluster
	ClusterName string

	// host
	HostName string
	HostIP   string

	// namespace name + container group name / host name -> corresponding security policies
	SecurityPolicies     map[string]tp.MatchPolicies
	SecurityPoliciesLock *sync.RWMutex

	// GKE
	IsGKE bool
}

// NewFeeder Function
func NewFeeder(clusterName, port, output, filter string) *Feeder {
	fd := &Feeder{}

	// set cluster info
	fd.ClusterName = clusterName

	// gRPC configuration
	fd.Port = fmt.Sprintf(":%s", port)

	// logging
	fd.Output = output
	fd.Filter = filter

	// output mode
	if fd.Output != "stdout" && fd.Output != "none" {
		// get the directory part from the path
		dirLog := filepath.Dir(fd.Output)

		// create directories
		if err := os.MkdirAll(filepath.Clean(dirLog), 0750); err != nil {
			kg.Errf("Failed to create a target directory (%s, %s)", dirLog, err.Error())
			return nil
		}

		// create target file
		targetFile, err := os.Create(filepath.Clean(fd.Output))
		if err != nil {
			kg.Errf("Failed to create a target file (%s, %s)", fd.Output, err.Error())
			return nil
		}
		if err := targetFile.Close(); err != nil {
			kg.Err(err.Error())
		}

		// open the file with the append mode
		fd.LogFile, err = os.OpenFile(filepath.Clean(fd.Output), os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			kg.Err(err.Error())
			return nil
		}
	}

	// listen to gRPC port
	listener, err := net.Listen("tcp", fd.Port)
	if err != nil {
		kg.Errf("Failed to listen a port (%s, %s)", fd.Port, err.Error())
		return nil
	}
	fd.Listener = listener

	// create a log server
	fd.LogServer = grpc.NewServer()

	// register a log service
	logService := &LogService{
		MsgStructs:   make(map[string]MsgStruct),
		MsgLock:      &sync.Mutex{},
		AlertStructs: make(map[string]AlertStruct),
		AlertLock:    &sync.Mutex{},
		LogStructs:   make(map[string]LogStruct),
		LogLock:      &sync.Mutex{},
	}
	pb.RegisterLogServiceServer(fd.LogServer, logService)

	// set wait group
	fd.WgServer = sync.WaitGroup{}

	// set host info
	fd.HostName = kl.GetHostName()
	fd.HostIP = kl.GetExternalIPAddr()

	// initialize security policies
	fd.SecurityPolicies = map[string]tp.MatchPolicies{}
	fd.SecurityPoliciesLock = new(sync.RWMutex)

	// check if GKE
	if kl.IsInK8sCluster() {
		if b, err := ioutil.ReadFile(filepath.Clean("/media/root/etc/os-release")); err == nil {
			s := string(b)
			if strings.Contains(s, "Container-Optimized OS") {
				fd.IsGKE = true
			}
		}
	}

	return fd
}

// DestroyFeeder Function
func (fd *Feeder) DestroyFeeder() error {
	// stop gRPC service
	Running = false

	// wait for a while
	time.Sleep(time.Second * 1)

	// close listener
	if fd.Listener != nil {
		if err := fd.Listener.Close(); err != nil {
			kg.Err(err.Error())
		}
		fd.Listener = nil
	}

	// close LogFile
	if fd.LogFile != nil {
		if err := fd.LogFile.Close(); err != nil {
			kg.Err(err.Error())
		}
		fd.LogFile = nil
	}

	// wait for other routines
	fd.WgServer.Wait()

	return nil
}

// StrToFile Function
func (fd *Feeder) StrToFile(str string) {
	if fd.LogFile != nil {
		// add the newline at the end of the string
		str = str + "\n"

		// write the string into the file
		w := bufio.NewWriter(fd.LogFile)
		if _, err := w.WriteString(str); err != nil {
			kg.Err(err.Error())
		}

		// flush the file buffer
		if err := w.Flush(); err != nil {
			kg.Err(err.Error())
		}
	}
}

// ============== //
// == Messages == //
// ============== //

// Print Function
func (fd *Feeder) Print(message string) {
	fd.PushMessage("INFO", message)
	kg.Print(message)
}

// Printf Function
func (fd *Feeder) Printf(message string, args ...interface{}) {
	str := fmt.Sprintf(message, args...)
	fd.PushMessage("INFO", str)
	kg.Print(str)
}

// Debug Function
func (fd *Feeder) Debug(message string) {
	fd.PushMessage("DEBUG", message)
	kg.Debug(message)
}

// Debugf Function
func (fd *Feeder) Debugf(message string, args ...interface{}) {
	str := fmt.Sprintf(message, args...)
	fd.PushMessage("DEBUG", str)
	kg.Debug(str)
}

// Err Function
func (fd *Feeder) Err(message string) {
	fd.PushMessage("ERROR", message)
	kg.Err(message)
}

// Errf Function
func (fd *Feeder) Errf(message string, args ...interface{}) {
	str := fmt.Sprintf(message, args...)
	fd.PushMessage("ERROR", str)
	kg.Err(str)
}

// =============== //
// == Log Feeds == //
// =============== //

// ServeLogFeeds Function
func (fd *Feeder) ServeLogFeeds() {
	fd.WgServer.Add(1)
	defer fd.WgServer.Done()

	// feed logs
	if err := fd.LogServer.Serve(fd.Listener); err != nil {
		kg.Print("Terminated the gRPC service")
	}
}

// PushMessage Function
func (fd *Feeder) PushMessage(level, message string) {
	pbMsg := pb.Message{}

	timestamp, updatedTime := kl.GetDateTimeNow()

	pbMsg.Timestamp = timestamp
	pbMsg.UpdatedTime = updatedTime

	pbMsg.ClusterName = fd.ClusterName

	pbMsg.HostName = fd.HostName
	pbMsg.HostIP = fd.HostIP

	pbMsg.Type = "Message"

	pbMsg.Level = level
	pbMsg.Message = message

	MsgQueue <- pbMsg
}

// PushLog Function
func (fd *Feeder) PushLog(log tp.Log) {
	log = fd.UpdateMatchedPolicy(log)

	if log.UpdatedTime == "" {
		return
	}

	// remove visibility flags
	log.PolicyEnabled = 0
	log.ProcessVisibilityEnabled = false
	log.FileVisibilityEnabled = false
	log.NetworkVisibilityEnabled = false
	log.CapabilitiesVisibilityEnabled = false

	// standard output / file output
	if fd.Filter == "policy" {
		if len(log.PolicyName) > 0 {
			log.HostName = fd.HostName

			if fd.Output == "stdout" {
				arr, _ := json.Marshal(log)
				fmt.Println(string(arr))
			} else if fd.Output != "none" {
				arr, _ := json.Marshal(log)
				fd.StrToFile(string(arr))
			}
		}
	} else if fd.Filter == "system" {
		if len(log.PolicyName) == 0 {
			log.HostName = fd.HostName

			if fd.Output == "stdout" {
				arr, _ := json.Marshal(log)
				fmt.Println(string(arr))
			} else if fd.Output != "none" {
				arr, _ := json.Marshal(log)
				fd.StrToFile(string(arr))
			}
		}
	} else { // all
		log.HostName = fd.HostName

		if fd.Output == "stdout" {
			arr, _ := json.Marshal(log)
			fmt.Println(string(arr))
		} else if fd.Output != "none" {
			arr, _ := json.Marshal(log)
			fd.StrToFile(string(arr))
		}
	}

	// gRPC output
	if log.Type == "MatchedPolicy" || log.Type == "MatchedNativePolicy" {
		pbAlert := pb.Alert{}

		pbAlert.Timestamp = log.Timestamp
		pbAlert.UpdatedTime = log.UpdatedTime

		pbAlert.ClusterName = fd.ClusterName
		pbAlert.HostName = fd.HostName

		pbAlert.NamespaceName = log.NamespaceName
		pbAlert.PodName = log.PodName
		pbAlert.ContainerID = log.ContainerID
		pbAlert.ContainerName = log.ContainerName

		pbAlert.HostPID = log.HostPID
		pbAlert.PPID = log.PPID
		pbAlert.PID = log.PID
		pbAlert.UID = log.UID

		if len(log.PolicyName) > 0 {
			pbAlert.PolicyName = log.PolicyName
		}

		if len(log.Severity) > 0 {
			pbAlert.Severity = log.Severity
		}

		if len(log.Tags) > 0 {
			pbAlert.Tags = log.Tags
		}

		if len(log.Message) > 0 {
			pbAlert.Message = log.Message
		}

		pbAlert.Type = log.Type
		pbAlert.Source = log.Source
		pbAlert.Operation = log.Operation
		pbAlert.Resource = log.Resource

		if len(log.Data) > 0 {
			pbAlert.Data = log.Data
		}

		if len(log.Action) > 0 {
			pbAlert.Action = log.Action
		}

		pbAlert.Result = log.Result

		AlertQueue <- pbAlert
	} else { // ContainerLog
		pbLog := pb.Log{}

		pbLog.Timestamp = log.Timestamp
		pbLog.UpdatedTime = log.UpdatedTime

		pbLog.ClusterName = fd.ClusterName
		pbLog.HostName = fd.HostName

		pbLog.NamespaceName = log.NamespaceName
		pbLog.PodName = log.PodName
		pbLog.ContainerID = log.ContainerID
		pbLog.ContainerName = log.ContainerName

		pbLog.HostPID = log.HostPID
		pbLog.PPID = log.PPID
		pbLog.PID = log.PID
		pbLog.UID = log.UID

		pbLog.Type = log.Type
		pbLog.Source = log.Source
		pbLog.Operation = log.Operation
		pbLog.Resource = log.Resource

		if len(log.Data) > 0 {
			pbLog.Data = log.Data
		}

		pbLog.Result = log.Result

		LogQueue <- pbLog
	}
}
