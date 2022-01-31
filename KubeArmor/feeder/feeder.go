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
	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	kg "github.com/kubearmor/KubeArmor/KubeArmor/log"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"

	"github.com/google/uuid"
	pb "github.com/kubearmor/KubeArmor/protobuf"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
	MsgLock    *sync.RWMutex

	AlertStructs map[string]AlertStruct
	AlertLock    *sync.RWMutex

	LogStructs map[string]LogStruct
	LogLock    *sync.RWMutex
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

	ls.MsgLock.RLock()
	defer ls.MsgLock.RUnlock()

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
			select {
			case <-svr.Context().Done():
				kg.Warn("conn closed exiting WatchMessages")
				return nil
			default:
				if status, ok := status.FromError(mgs.Client.Send(&msg)); ok {
					switch status.Code() {
					case codes.OK:
						//noop
					case codes.Unavailable, codes.Canceled, codes.DeadlineExceeded:
						kg.Warnf("Failed to send a message=[%+v] err=[%s]", msg, status.Err().Error())
						return status.Err()
					default:
						return nil
					}
				}
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

	ls.AlertLock.RLock()
	defer ls.AlertLock.RUnlock()

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
			select {
			case <-svr.Context().Done():
				kg.Warn("conn closed exiting WatchAlerts")
				return nil
			default:
				if status, ok := status.FromError(als.Client.Send(&alert)); ok {
					switch status.Code() {
					case codes.OK:
						//noop
					case codes.Unavailable, codes.Canceled, codes.DeadlineExceeded:
						kg.Warnf("Failed to send an alert=[%+v] err=[%s]", alert, status.Err().Error())
						return status.Err()
					default:
						return nil
					}
				}
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

	ls.LogLock.RLock()
	defer ls.LogLock.RUnlock()

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
			select {
			case <-svr.Context().Done():
				kg.Warn("conn closed exiting WatchLogs")
				return nil
			default:
				if status, ok := status.FromError(lgs.Client.Send(&log)); ok {
					switch status.Code() {
					case codes.OK:
						//noop
					case codes.Unavailable, codes.Canceled, codes.DeadlineExceeded:
						kg.Warnf("Failed to send a log=[%+v] err=[%s]", log, status.Err().Error())
						return status.Err()
					default:
						return nil
					}
				}
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
	// node
	Node *tp.Node

	// port
	Port string

	// output
	Output  string
	LogFile *os.File

	// gRPC listener
	Listener net.Listener

	// log server
	LogServer *grpc.Server

	// wait group
	WgServer sync.WaitGroup

	// namespace name + endpoint name / host name -> corresponding security policies
	SecurityPolicies     map[string]tp.MatchPolicies
	SecurityPoliciesLock *sync.RWMutex

	// GKE
	IsGKE bool
}

// NewFeeder Function
func NewFeeder(node *tp.Node) *Feeder {
	fd := &Feeder{}

	// node
	fd.Node = node

	// gRPC configuration
	fd.Port = fmt.Sprintf(":%s", cfg.GlobalCfg.GRPC)

	// output
	fd.Output = cfg.GlobalCfg.LogPath

	// output mode
	if fd.Output != "stdout" && fd.Output != "none" {
		// #nosec
		logFile, err := os.OpenFile(filepath.Clean(fd.Output), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			kg.Errf("Failed to open %s", fd.Output)
			return nil
		}
		fd.LogFile = logFile
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
		MsgLock:      &sync.RWMutex{},
		AlertStructs: make(map[string]AlertStruct),
		AlertLock:    &sync.RWMutex{},
		LogStructs:   make(map[string]LogStruct),
		LogLock:      &sync.RWMutex{},
	}
	pb.RegisterLogServiceServer(fd.LogServer, logService)

	// set wait group
	fd.WgServer = sync.WaitGroup{}

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

// Warn Function
func (fd *Feeder) Warn(message string) {
	fd.PushMessage("WARN", message)
	kg.Warn(message)
}

// Warnf Function
func (fd *Feeder) Warnf(message string, args ...interface{}) {
	str := fmt.Sprintf(message, args...)
	fd.PushMessage("WARN", str)
	kg.Warnf(str)
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

	pbMsg.ClusterName = cfg.GlobalCfg.Cluster

	pbMsg.HostName = cfg.GlobalCfg.Host
	pbMsg.HostIP = fd.Node.NodeIP

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

	// set hostname
	log.HostName = cfg.GlobalCfg.Host

	// remove MergedDir
	log.MergedDir = ""

	// remove flags
	log.PolicyEnabled = 0
	log.ProcessVisibilityEnabled = false
	log.FileVisibilityEnabled = false
	log.NetworkVisibilityEnabled = false
	log.CapabilitiesVisibilityEnabled = false

	// standard output / file output
	if fd.Output == "stdout" {
		arr, _ := json.Marshal(log)
		fmt.Println(string(arr))
	} else if fd.Output != "none" {
		arr, _ := json.Marshal(log)
		fd.StrToFile(string(arr))
	}

	// gRPC output
	if log.Type == "MatchedPolicy" || log.Type == "MatchedHostPolicy" || log.Type == "MatchedNativePolicy" {
		pbAlert := pb.Alert{}

		pbAlert.Timestamp = log.Timestamp
		pbAlert.UpdatedTime = log.UpdatedTime

		pbAlert.ClusterName = cfg.GlobalCfg.Cluster
		pbAlert.HostName = cfg.GlobalCfg.Host

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
		pbAlert.Resource = strings.ToValidUTF8(log.Resource, "")

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

		pbLog.ClusterName = cfg.GlobalCfg.Cluster
		pbLog.HostName = cfg.GlobalCfg.Host

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
		pbLog.Resource = strings.ToValidUTF8(log.Resource, "")

		if len(log.Data) > 0 {
			pbLog.Data = log.Data
		}

		pbLog.Result = log.Result

		LogQueue <- pbLog
	}
}
