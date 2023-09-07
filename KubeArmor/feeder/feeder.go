// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

// Package feeder is responsible for sanitizing and relaying telemetry and alerts data to connected clients
package feeder

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
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

const QueueSize = 1000

func init() {
	Running = true
}

// ========== //
// == gRPC == //
// ========== //

// MsgStruct Structure
type MsgStruct struct {
	Filter    string
	Broadcast chan *pb.Message
}

// MsgStructs Map
var MsgStructs map[string]MsgStruct

// MsgLock Lock
var MsgLock *sync.RWMutex

// AlertStruct Structure
type AlertStruct struct {
	Filter    string
	Broadcast chan *pb.Alert
}

// AlertStructs Map
var AlertStructs map[string]AlertStruct

// AlertLock Lock
var AlertLock *sync.RWMutex

// LogStruct Structure
type LogStruct struct {
	Filter    string
	Broadcast chan *pb.Log
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
func (ls *LogService) addMsgStruct(uid string, conn chan *pb.Message, filter string) {
	MsgLock.Lock()
	defer MsgLock.Unlock()

	msgStruct := MsgStruct{}
	msgStruct.Filter = filter
	msgStruct.Broadcast = conn
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
	conn := make(chan *pb.Message, QueueSize)
	defer close(conn)
	ls.addMsgStruct(uid, conn, req.Filter)
	defer ls.removeMsgStruct(uid)

	for Running {
		select {
		case <-svr.Context().Done():
			return nil
		case resp := <-conn:
			if status, ok := status.FromError(svr.Send(resp)); ok {
				switch status.Code() {
				case codes.OK:
					// noop
				case codes.Unavailable, codes.Canceled, codes.DeadlineExceeded:
					kg.Warnf("Failed to send a message=[%+v] err=[%s]", resp, status.Err().Error())
					return status.Err()
				default:
					return nil
				}
			}
		}
	}

	return nil
}

// addAlertStruct Function
func (ls *LogService) addAlertStruct(uid string, conn chan *pb.Alert, filter string) {
	AlertLock.Lock()
	defer AlertLock.Unlock()

	alertStruct := AlertStruct{}
	alertStruct.Filter = filter
	alertStruct.Broadcast = conn
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
	conn := make(chan *pb.Alert, QueueSize)
	defer close(conn)
	ls.addAlertStruct(uid, conn, req.Filter)
	defer ls.removeAlertStruct(uid)

	for Running {
		select {
		case <-svr.Context().Done():
			return nil
		case resp := <-conn:
			if status, ok := status.FromError(svr.Send(resp)); ok {
				switch status.Code() {
				case codes.OK:
					// noop
				case codes.Unavailable, codes.Canceled, codes.DeadlineExceeded:
					kg.Warnf("Failed to send an alert=[%+v] err=[%s]", resp, status.Err().Error())
					return status.Err()
				default:
					return nil
				}
			}
		}
	}

	return nil
}

// addLogStruct Function
func (ls *LogService) addLogStruct(uid string, conn chan *pb.Log, filter string) {
	LogLock.Lock()
	defer LogLock.Unlock()

	logStruct := LogStruct{}
	logStruct.Filter = filter
	logStruct.Broadcast = conn
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
	conn := make(chan *pb.Log, QueueSize)
	defer close(conn)
	ls.addLogStruct(uid, conn, req.Filter)
	defer ls.removeLogStruct(uid)

	for Running {
		select {
		case <-svr.Context().Done():
			return nil
		case resp := <-conn:
			if status, ok := status.FromError(svr.Send(resp)); ok {
				switch status.Code() {
				case codes.OK:
					// noop
				case codes.Unavailable, codes.Canceled, codes.DeadlineExceeded:
					kg.Warnf("Failed to send a log=[%+v] err=[%s] CODE=%d", resp, status.Err().Error(), status.Code())
					return status.Err()
				default:
					return nil
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
	Node     *tp.Node
	NodeLock **sync.RWMutex

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

	// DefaultPosture (namespace -> postures)
	DefaultPostures     map[string]tp.DefaultPosture
	DefaultPosturesLock *sync.Mutex

	// GKE
	IsGKE bool

	// Activated Enforcer
	Enforcer string
}

// NewFeeder Function
func NewFeeder(node *tp.Node, nodeLock **sync.RWMutex) *Feeder {
	fd := &Feeder{}

	// node
	fd.Node = node
	fd.NodeLock = nodeLock

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

	if cfg.GlobalCfg.GRPC == "0" {
		pidFile, err := os.Create(cfg.PIDFilePath)
		if err != nil {
			kg.Errf("Failed to create file %s", cfg.PIDFilePath)
			return nil
		}

		defer func() {
			err := pidFile.Close()
			if err != nil {
				kg.Errf("Failed to close file %s", cfg.PIDFilePath)
			}
		}()

		port := fmt.Sprintf("%d", listener.Addr().(*net.TCPAddr).Port)
		fd.Port = fmt.Sprintf(":%s", port)

		_, err = pidFile.WriteString(port)
		if err != nil {
			kg.Errf("Failed to write file %s", cfg.PIDFilePath)
			return nil
		}
	}

	// create a log server
	fd.LogServer = grpc.NewServer()

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

	// initialize default postures
	fd.DefaultPostures = map[string]tp.DefaultPosture{}
	fd.DefaultPosturesLock = new(sync.Mutex)

	// check if GKE
	if kl.IsInK8sCluster() {
		if b, err := os.ReadFile(filepath.Clean("/media/root/etc/os-release")); err == nil {
			s := string(b)
			if strings.Contains(s, "Container-Optimized OS") {
				fd.IsGKE = true
			}
		}
	}

	// default enforcer
	fd.Enforcer = "eBPF Monitor"

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

// ===================== //
// == Enforcer Update == //
// ===================== //

// UpdateEnforcer Function
func (fd *Feeder) UpdateEnforcer(enforcer string) {
	fd.Enforcer = enforcer
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
	counter := 0
	lenMsg := len(MsgStructs)
	for uid := range MsgStructs {
		select {
		case MsgStructs[uid].Broadcast <- &pbMsg:
		default:
			counter++
			if counter == lenMsg {
				//Default on the last uid in Messagestruct means the msg isnt pushed into Broadcast
				kg.Printf("msg channel busy, msg dropped")
			}

		}
	}
}

// PushLog Function
func (fd *Feeder) PushLog(log tp.Log) {
	log = fd.UpdateMatchedPolicy(log)

	if log.Source == "" {
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
	if log.Type == "MatchedPolicy" || log.Type == "MatchedHostPolicy" {
		pbAlert := pb.Alert{}

		pbAlert.Timestamp = log.Timestamp
		pbAlert.UpdatedTime = log.UpdatedTime

		pbAlert.ClusterName = fd.Node.ClusterName
		pbAlert.HostName = fd.Node.NodeName

		pbAlert.NamespaceName = log.NamespaceName

		var owner *pb.Podowner
		if log.Owner != nil && (log.Owner.Ref != "" || log.Owner.Name != "" || log.Owner.Namespace != "") {
			owner = &pb.Podowner{
				Ref:       log.Owner.Ref,
				Name:      log.Owner.Name,
				Namespace: log.Owner.Namespace,
			}
		}

		if pbAlert.Owner == nil && owner != nil {
			pbAlert.Owner = owner
		}

		pbAlert.PodName = log.PodName
		pbAlert.Labels = log.Labels

		pbAlert.ContainerID = log.ContainerID
		pbAlert.ContainerName = log.ContainerName
		pbAlert.ContainerImage = log.ContainerImage

		pbAlert.HostPPID = log.HostPPID
		pbAlert.HostPID = log.HostPID

		pbAlert.PPID = log.PPID
		pbAlert.PID = log.PID
		pbAlert.UID = log.UID

		pbAlert.ParentProcessName = log.ParentProcessName
		pbAlert.ProcessName = log.ProcessName

		if len(log.Enforcer) > 0 {
			pbAlert.Enforcer = log.Enforcer
		}

		if len(log.PolicyName) > 0 {
			pbAlert.PolicyName = log.PolicyName
		}

		if len(log.Severity) > 0 {
			pbAlert.Severity = log.Severity
		}

		if len(log.Tags) > 0 {
			pbAlert.Tags = log.Tags
			pbAlert.ATags = strings.Split(log.Tags, ",")
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

		AlertLock.Lock()
		defer AlertLock.Unlock()
		counter := 0
		lenAlert := len(AlertStructs)

		for uid := range AlertStructs {
			select {
			case AlertStructs[uid].Broadcast <- &pbAlert:
			default:
				counter++
				if counter == lenAlert {
					//Default on the last uid in Alterstruct means the Alert isnt pushed into Broadcast
					kg.Printf("log channel busy, alert dropped.")
				}

			}
		}
	} else { // ContainerLog || HostLog
		pbLog := pb.Log{}

		pbLog.Timestamp = log.Timestamp
		pbLog.UpdatedTime = log.UpdatedTime

		pbLog.ClusterName = fd.Node.ClusterName
		pbLog.HostName = fd.Node.NodeName

		pbLog.NamespaceName = log.NamespaceName

		var owner *pb.Podowner
		if log.Owner != nil && (log.Owner.Ref != "" || log.Owner.Name != "" || log.Owner.Namespace != "") {
			owner = &pb.Podowner{
				Ref:       log.Owner.Ref,
				Name:      log.Owner.Name,
				Namespace: log.Owner.Namespace,
			}
		}

		if pbLog.Owner == nil && owner != nil {
			pbLog.Owner = owner
		}

		pbLog.PodName = log.PodName
		pbLog.Labels = log.Labels

		pbLog.ContainerID = log.ContainerID
		pbLog.ContainerName = log.ContainerName
		pbLog.ContainerImage = log.ContainerImage

		pbLog.HostPPID = log.HostPPID
		pbLog.HostPID = log.HostPID

		pbLog.PPID = log.PPID
		pbLog.PID = log.PID
		pbLog.UID = log.UID

		pbLog.ParentProcessName = log.ParentProcessName
		pbLog.ProcessName = log.ProcessName

		pbLog.Type = log.Type
		pbLog.Source = log.Source
		pbLog.Operation = log.Operation
		pbLog.Resource = strings.ToValidUTF8(log.Resource, "")

		if len(log.Data) > 0 {
			pbLog.Data = log.Data
		}

		pbLog.Result = log.Result

		LogLock.Lock()
		defer LogLock.Unlock()
		counter := 0
		lenlog := len(LogStructs)
		for uid := range LogStructs {
			select {
			case LogStructs[uid].Broadcast <- &pbLog:
			default:
				counter++
				if counter == lenlog {
					//Default on the last uid in Logstuct means the log isnt pushed into Broadcase
					kg.Printf("log channel busy, log dropped.")
				}
			}
		}
	}
}
