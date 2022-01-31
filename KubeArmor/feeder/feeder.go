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
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"
)

// ============ //
// == Global == //
// ============ //

// Running flag
var Running bool

func init() {
	Running = true
}

// ========== //
// == gRPC == //
// ========== //

// MsgStruct Structure
type MsgStruct struct {
	Filter string
	Queue  *kl.Queue
}

// MsgStructs Map
var MsgStructs map[string]MsgStruct

// MsgLock Lock
var MsgLock *sync.RWMutex

// AlertStruct Structure
type AlertStruct struct {
	Filter string
	Queue  *kl.Queue
}

// AlertStructs Map
var AlertStructs map[string]AlertStruct

// AlertLock Lock
var AlertLock *sync.RWMutex

// LogStruct Structure
type LogStruct struct {
	Filter string
	Queue  *kl.Queue
}

// LogStructs Map
var LogStructs map[string]LogStruct

// LogLock Lock
var LogLock *sync.RWMutex

// LogService Structure
type LogService struct {
	//
}

// HealthCheck Function
func (ls *LogService) HealthCheck(ctx context.Context, nonce *pb.NonceMessage) (*pb.ReplyMessage, error) {
	replyMessage := pb.ReplyMessage{Retval: nonce.Nonce}
	return &replyMessage, nil
}

// addMsgStruct Function
func (ls *LogService) addMsgStruct(uid string, filter string) {
	MsgLock.Lock()
	defer MsgLock.Unlock()

	msgStruct := MsgStruct{}
	msgStruct.Filter = filter
	msgStruct.Queue = kl.NewQueue()

	MsgStructs[uid] = msgStruct

	kg.Printf("Added a new client (%s) for WatchMessages", uid)
}

// removeMsgStruct Function
func (ls *LogService) removeMsgStruct(uid string) {
	MsgLock.Lock()
	defer MsgLock.Unlock()

	delete(MsgStructs, uid)

	kg.Printf("Deleted the client (%s) for WatchMessages", uid)
}

// WatchMessages Function
func (ls *LogService) WatchMessages(req *pb.RequestMessage, svr pb.LogService_WatchMessagesServer) error {
	uid := uuid.Must(uuid.NewRandom()).String()

	ls.addMsgStruct(uid, req.Filter)
	defer ls.removeMsgStruct(uid)

	for Running {
		select {
		case <-svr.Context().Done():
			return nil
		default:
			if msgInt := MsgStructs[uid].Queue.Pop(); msgInt != nil {
				msg := msgInt.(pb.Message)
				if status, ok := status.FromError(svr.Send(&msg)); ok {
					switch status.Code() {
					case codes.OK:
						// noop
					case codes.Unavailable, codes.Canceled, codes.DeadlineExceeded:
						kg.Warnf("Failed to send a message=[%+v] err=[%s]", msg, status.Err().Error())
						return status.Err()
					default:
						return nil
					}
				}
			} else {
				time.Sleep(time.Second * 1)
			}
		}
	}

	return nil
}

// addAlertStruct Function
func (ls *LogService) addAlertStruct(uid string, filter string) {
	AlertLock.Lock()
	defer AlertLock.Unlock()

	alertStruct := AlertStruct{}
	alertStruct.Filter = filter
	alertStruct.Queue = kl.NewQueue()

	AlertStructs[uid] = alertStruct

	kg.Printf("Added a new client (%s, %s) for WatchAlerts", uid, filter)
}

// removeAlertStruct Function
func (ls *LogService) removeAlertStruct(uid string) {
	AlertLock.Lock()
	defer AlertLock.Unlock()

	delete(AlertStructs, uid)

	kg.Printf("Deleted the client (%s) for WatchAlerts", uid)
}

// WatchAlerts Function
func (ls *LogService) WatchAlerts(req *pb.RequestMessage, svr pb.LogService_WatchAlertsServer) error {
	uid := uuid.Must(uuid.NewRandom()).String()

	if req.Filter != "all" && req.Filter != "policy" {
		return nil
	}

	ls.addAlertStruct(uid, req.Filter)
	defer ls.removeAlertStruct(uid)

	for Running {
		select {
		case <-svr.Context().Done():
			return nil
		default:
			if alertInt := AlertStructs[uid].Queue.Pop(); alertInt != nil {
				alert := alertInt.(pb.Alert)
				if status, ok := status.FromError(svr.Send(&alert)); ok {
					switch status.Code() {
					case codes.OK:
						// noop
					case codes.Unavailable, codes.Canceled, codes.DeadlineExceeded:
						kg.Warnf("Failed to send an alert=[%+v] err=[%s]", alert, status.Err().Error())
						return status.Err()
					default:
						return nil
					}
				}
			} else {
				time.Sleep(time.Second * 1)
			}
		}
	}

	return nil
}

// addLogStruct Function
func (ls *LogService) addLogStruct(uid string, filter string) {
	LogLock.Lock()
	defer LogLock.Unlock()

	logStruct := LogStruct{}
	logStruct.Filter = filter
	logStruct.Queue = kl.NewQueue()

	LogStructs[uid] = logStruct

	kg.Printf("Added a new client (%s, %s) for WatchLogs", uid, filter)
}

// removeLogStruct Function
func (ls *LogService) removeLogStruct(uid string) {
	LogLock.Lock()
	defer LogLock.Unlock()

	delete(LogStructs, uid)

	kg.Printf("Deleted the client (%s) for WatchLogs", uid)
}

// WatchLogs Function
func (ls *LogService) WatchLogs(req *pb.RequestMessage, svr pb.LogService_WatchLogsServer) error {
	uid := uuid.Must(uuid.NewRandom()).String()

	if req.Filter != "all" && req.Filter != "system" {
		return nil
	}

	ls.addLogStruct(uid, req.Filter)
	defer ls.removeLogStruct(uid)

	for Running {
		select {
		case <-svr.Context().Done():
			return nil
		default:
			if logInt := LogStructs[uid].Queue.Pop(); logInt != nil {
				log := logInt.(pb.Log)
				if status, ok := status.FromError(svr.Send(&log)); ok {
					switch status.Code() {
					case codes.OK:
						// noop
					case codes.Unavailable, codes.Canceled, codes.DeadlineExceeded:
						kg.Warnf("Failed to send a log=[%+v] err=[%s]", log, status.Err().Error())
						return status.Err()
					default:
						return nil
					}
				}
			} else {
				time.Sleep(time.Second * 1)
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

	kaep := keepalive.EnforcementPolicy{
		PermitWithoutStream: true,
	}

	kasp := keepalive.ServerParameters{
		Time:    1 * time.Second,
		Timeout: 1 * time.Second,
	}

	// create a log server
	fd.LogServer = grpc.NewServer(grpc.KeepaliveEnforcementPolicy(kaep), grpc.KeepaliveParams(kasp))

	// register a log service
	logService := &LogService{}
	pb.RegisterLogServiceServer(fd.LogServer, logService)

	// initialize msg structs
	MsgStructs = make(map[string]MsgStruct)
	MsgLock = &sync.RWMutex{}

	// initialize alert structs
	AlertStructs = make(map[string]AlertStruct)
	AlertLock = &sync.RWMutex{}

	// initialize log structs
	LogStructs = make(map[string]LogStruct)
	LogLock = &sync.RWMutex{}

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

	MsgLock.Lock()
	defer MsgLock.Unlock()

	for uid := range MsgStructs {
		MsgStructs[uid].Queue.Push(pbMsg)
	}
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
		pbAlert.Resource = log.Resource

		if len(log.Data) > 0 {
			pbAlert.Data = log.Data
		}

		if len(log.Action) > 0 {
			pbAlert.Action = log.Action
		}

		pbAlert.Result = log.Result

		AlertLock.Lock()
		defer AlertLock.Unlock()

		for uid := range AlertStructs {
			AlertStructs[uid].Queue.Push(pbAlert)
		}
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
		pbLog.Resource = log.Resource

		if len(log.Data) > 0 {
			pbLog.Data = log.Data
		}

		pbLog.Result = log.Result

		LogLock.Lock()
		defer LogLock.Unlock()

		for uid := range LogStructs {
			LogStructs[uid].Queue.Push(pbLog)
		}
	}
}
