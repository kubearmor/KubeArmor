// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

// Package feeder is responsible for sanitizing and relaying telemetry and alerts data to connected clients
package feeder

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/kubearmor/KubeArmor/KubeArmor/common"
	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	"github.com/kubearmor/KubeArmor/KubeArmor/config"
	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	kg "github.com/kubearmor/KubeArmor/KubeArmor/log"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"

	"github.com/google/uuid"
	"github.com/kubearmor/KubeArmor/KubeArmor/cert"
	pb "github.com/kubearmor/KubeArmor/protobuf"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
)

// ============ //
// == Global == //
// ============ //

// Running flag
var Running bool

// QueueSize
const QueueSize = 1000

// metricsServerOnce ensures metrics endpoint is registered only once
var metricsServerOnce sync.Once

func init() {
	Running = true
}

// ========== //
// == gRPC == //
// ========== //

// EventStruct Structure
type EventStruct[T any] struct {
	Filter    string
	Broadcast chan *T
}

type EventStructs struct {
	MsgStructs map[string]EventStruct[pb.Message]
	MsgLock    sync.RWMutex

	AlertStructs map[string]EventStruct[pb.Alert]
	AlertLock    sync.RWMutex

	LogStructs map[string]EventStruct[pb.Log]
	LogLock    sync.RWMutex
}

// AddMsgStruct Function
func (es *EventStructs) AddMsgStruct(filter string, queueSize int) (string, chan *pb.Message) {
	es.MsgLock.Lock()
	defer es.MsgLock.Unlock()

	uid := uuid.Must(uuid.NewRandom()).String()
	conn := make(chan *pb.Message, queueSize)

	msgStruct := EventStruct[pb.Message]{
		Filter:    filter,
		Broadcast: conn,
	}

	es.MsgStructs[uid] = msgStruct

	return uid, conn
}

// RemoveMsgStruct Function
func (es *EventStructs) RemoveMsgStruct(uid string) {
	es.MsgLock.Lock()
	defer es.MsgLock.Unlock()

	delete(es.MsgStructs, uid)
}

// AddAlertStruct Function
func (es *EventStructs) AddAlertStruct(filter string, queueSize int) (string, chan *pb.Alert) {
	es.AlertLock.Lock()
	defer es.AlertLock.Unlock()

	uid := uuid.Must(uuid.NewRandom()).String()
	conn := make(chan *pb.Alert, queueSize)

	alertStruct := EventStruct[pb.Alert]{
		Filter:    filter,
		Broadcast: conn,
	}

	es.AlertStructs[uid] = alertStruct

	return uid, conn
}

// removeAlertStruct Function
func (es *EventStructs) RemoveAlertStruct(uid string) {
	es.AlertLock.Lock()
	defer es.AlertLock.Unlock()

	delete(es.AlertStructs, uid)
}

// addLogStruct Function
func (es *EventStructs) AddLogStruct(filter string, queueSize int) (string, chan *pb.Log) {
	es.LogLock.Lock()
	defer es.LogLock.Unlock()

	uid := uuid.Must(uuid.NewRandom()).String()
	conn := make(chan *pb.Log, queueSize)

	logStruct := EventStruct[pb.Log]{
		Filter:    filter,
		Broadcast: conn,
	}

	es.LogStructs[uid] = logStruct

	return uid, conn
}

// removeLogStruct Function
func (es *EventStructs) RemoveLogStruct(uid string) {
	es.LogLock.Lock()
	defer es.LogLock.Unlock()

	delete(es.LogStructs, uid)
}

// ============ //
// == Feeder == //
// ============ //
type FeederInterface interface {
	// Methods

	// How does the feeder pushes logs and messages
	PushLog(tp.Log)
	PushMessage(string, string)

	// How does this feeder match log with policy
	UpdateMatchedPolicy(tp.Log)

	// How this feeder serves log feeds
	ServeLogFeeds()
}

type BaseFeeder struct {
	// node
	Node     *tp.Node
	NodeLock **sync.RWMutex

	// wait group
	WgServer sync.WaitGroup

	// output
	Output  string
	LogFile *os.File

	// Activated Enforcer
	Enforcer     string
	EnforcerLock *sync.RWMutex

	// Msg, log and alert connection stores
	EventStructs *EventStructs

	// True if feeder and its workers are working
	Running bool

	// LogServer //

	// port
	Port string

	// gRPC listener
	Listener net.Listener

	// log server
	LogServer *grpc.Server
}

type OuterKey struct {
	PidNs uint32
	MntNs uint32
}

type AlertThrottleState struct {
	FirstEventTimestamp uint64
	EventCount          uint64
	Throttle            bool
}

// Feeder Structure
type Feeder struct {
	BaseFeeder

	// KubeArmor feeder //

	// namespace name + endpoint name / host name -> corresponding security policies
	SecurityPolicies     map[string]tp.MatchPolicies
	SecurityPoliciesLock *sync.RWMutex

	// DefaultPosture (namespace -> postures)
	DefaultPostures     map[string]tp.DefaultPosture
	DefaultPosturesLock *sync.Mutex

	AlertMap map[OuterKey]AlertThrottleState

	ContainerNsKey map[string]common.OuterKey

	// Policy metadata tracking for metrics
	PolicyMetadata     map[string]PolicyMetricInfo
	PolicyMetadataLock *sync.RWMutex
}

// PolicyMetricInfo stores policy information for metrics
type PolicyMetricInfo struct {
	Name      string
	Namespace string
	Type      string // "KubeArmorPolicy", "KubeArmorHostPolicy", "KubeArmorClusterPolicy"
	Status    string // "active"
}

// NewFeeder Function
func NewFeeder(node *tp.Node, nodeLock **sync.RWMutex) *Feeder {
	fd := &Feeder{}

	// base feeder //

	// node
	fd.Node = node
	fd.NodeLock = nodeLock

	// set wait group
	fd.WgServer = sync.WaitGroup{}

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

	// default enforcer
	fd.Enforcer = "eBPF Monitor"
	fd.EnforcerLock = new(sync.RWMutex)

	// initialize msg structs
	fd.EventStructs = &EventStructs{
		MsgStructs: make(map[string]EventStruct[pb.Message]),
		MsgLock:    sync.RWMutex{},

		// initialize alert structs
		AlertStructs: make(map[string]EventStruct[pb.Alert]),
		AlertLock:    sync.RWMutex{},

		// initialize log structs
		LogStructs: make(map[string]EventStruct[pb.Log]),
		LogLock:    sync.RWMutex{},
	}

	fd.Running = true

	// LogServer //

	// gRPC configuration
	fd.Port = fmt.Sprintf(":%s", cfg.GlobalCfg.GRPC)

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

	logService := &LogService{
		QueueSize:    1000,
		Running:      &fd.Running,
		EventStructs: fd.EventStructs,
	}

	kaep := keepalive.EnforcementPolicy{
		PermitWithoutStream: true,
	}
	kasp := keepalive.ServerParameters{
		Time:    1 * time.Second,
		Timeout: 5 * time.Second,
	}

	if cfg.GlobalCfg.TLSEnabled {
		tlsCredentials, err := loadTLSCredentials(node.NodeIP)
		if err != nil {
			kg.Errf("cannot load TLS credentials: %s", err)
			return nil
		}
		kg.Print("Server started with tls enabled")
		// create a log server
		fd.LogServer = grpc.NewServer(
			grpc.Creds(tlsCredentials),
			grpc.KeepaliveEnforcementPolicy(kaep),
			grpc.KeepaliveParams(kasp),
		)
	} else {
		fd.LogServer = grpc.NewServer(grpc.KeepaliveEnforcementPolicy(kaep), grpc.KeepaliveParams(kasp))
	}

	pb.RegisterLogServiceServer(fd.LogServer, logService)

	// Feeder //

	// initialize security policies
	fd.SecurityPolicies = map[string]tp.MatchPolicies{}
	fd.SecurityPoliciesLock = new(sync.RWMutex)

	// initialize default postures
	fd.DefaultPostures = map[string]tp.DefaultPosture{}
	fd.DefaultPosturesLock = new(sync.Mutex)

	// initialize policy metadata tracking for metrics
	fd.PolicyMetadata = make(map[string]PolicyMetricInfo)
	fd.PolicyMetadataLock = new(sync.RWMutex)

	// Start metrics server
	fd.StartMetricsServer()

	return fd
}

// StartMetricsServer starts the HTTP server for Prometheus metrics
func (fd *Feeder) StartMetricsServer() {
	metricsAddr := ":8080"

	// Register /metrics endpoint only once globally
	metricsServerOnce.Do(func() {
		http.Handle("/metrics", promhttp.Handler())
		kg.Printf("Registered /metrics endpoint")
	})

	kg.Printf("Starting metrics server on %s", metricsAddr)

	// Create server with timeouts to prevent slowloris attacks
	server := &http.Server{
		Addr:         metricsAddr,
		Handler:      nil, // Use DefaultServeMux
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			kg.Warnf("Metrics server failed: %s", err.Error())
		}
	}()
}

// updatePolicyMetric adds or updates a policy metric
func (fd *Feeder) updatePolicyMetric(info PolicyMetricInfo) {
	fd.PolicyMetadataLock.Lock()
	defer fd.PolicyMetadataLock.Unlock()

	// Store metadata
	fd.PolicyMetadata[info.Name] = info

	// Update Prometheus metrics
	PolicyInfo.WithLabelValues(
		info.Name,
		info.Namespace,
		info.Type,
		info.Status,
	).Set(1)

	// Update total count by type
	fd.updatePolicyCount()
}

// removePolicyMetric removes a policy from metrics
func (fd *Feeder) removePolicyMetric(policyName string) {
	fd.PolicyMetadataLock.Lock()
	defer fd.PolicyMetadataLock.Unlock()

	if info, exists := fd.PolicyMetadata[policyName]; exists {
		// Remove from Prometheus
		PolicyInfo.DeleteLabelValues(
			info.Name,
			info.Namespace,
			info.Type,
			info.Status,
		)

		// Remove from tracking map
		delete(fd.PolicyMetadata, policyName)

		// Update total count
		fd.updatePolicyCount()
	}
}

// updatePolicyCount recalculates and updates policy counts by type
func (fd *Feeder) updatePolicyCount() {
	typeCounts := map[string]int{
		"KubeArmorPolicy":        0,
		"KubeArmorHostPolicy":    0,
		"KubeArmorClusterPolicy": 0,
	}

	for _, info := range fd.PolicyMetadata {
		typeCounts[info.Type]++
	}

	for policyType, count := range typeCounts {
		PoliciesTotal.WithLabelValues(policyType).Set(float64(count))
	}
}

// DestroyFeeder Function
func (fd *BaseFeeder) DestroyFeeder() error {
	// stop gRPC service
	fd.Running = false

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
	fd.EnforcerLock.Lock()
	fd.Enforcer = enforcer
	fd.EnforcerLock.Unlock()
}

// =============== //
// == Log Feeds == //
// =============== //

// ServeLogFeeds Function
func (fd *BaseFeeder) ServeLogFeeds() {
	fd.WgServer.Add(1)
	defer fd.WgServer.Done()

	// feed logs
	if err := fd.LogServer.Serve(fd.Listener); err != nil {
		kg.Print("Terminated the gRPC service")
	}
}

// PushMessage Function
func (fd *Feeder) PushMessage(level, message string) {
	if !cfg.GlobalCfg.Debug {
		// Only Push Message over GRPC when Debug Mode
		return
	}

	pbMsg := pb.Message{}

	timestamp, updatedTime := kl.GetDateTimeNow()

	pbMsg.Timestamp = timestamp
	pbMsg.UpdatedTime = updatedTime

	//pbMsg.ClusterName = cfg.GlobalCfg.Cluster
	pbMsg.ClusterName = cfg.GlobalCfg.Cluster

	pbMsg.HostName = cfg.GlobalCfg.Host
	pbMsg.HostIP = fd.Node.NodeIP

	pbMsg.Type = "Message"

	pbMsg.Level = level
	pbMsg.Message = message

	// broadcast to all logserver and reverselogserver receivers
	fd.EventStructs.MsgLock.Lock()
	defer fd.EventStructs.MsgLock.Unlock()
	counter := 0
	lenMsg := len(fd.EventStructs.MsgStructs)
	for uid := range fd.EventStructs.MsgStructs {
		select {
		case fd.EventStructs.MsgStructs[uid].Broadcast <- &pbMsg:
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
	/* if enforcer == BPFLSM and log.Enforcer == ebpfmonitor ( block and default Posture Alerts from System
	   monitor are converted to host/container logs)
	   in case of enforcer = AppArmor only Default Posture logs will be converted to
	   container/host log depending upon the defaultPostureLogs flag
	*/
	isBPFLSM := fd.GetEnforcer() == "BPFLSM"
	if !common.IsPresetEnforcer(log.Enforcer) {
		if (cfg.GlobalCfg.EnforcerAlerts && isBPFLSM && log.Enforcer == "") || (!isBPFLSM && !cfg.GlobalCfg.DefaultPostureLogs) {
			log = fd.UpdateMatchedPolicy(log)
			isDefaultPostureLog := strings.Contains(log.PolicyName, "DefaultPosture")
			isAudit := strings.Contains(log.Action, "Audit")
			if (log.Type == "MatchedPolicy" || log.Type == "MatchedHostPolicy") && ((isBPFLSM && (isDefaultPostureLog || !isAudit)) || (!isBPFLSM && isDefaultPostureLog)) {
				switch log.Type {
				case "MatchedPolicy":
					log.Type = "ContainerLog"
				case "MatchedHostPolicy":
					log.Type = "HostLog"
				}
			}
		} else {
			log = fd.UpdateMatchedPolicy(log)
			if isBPFLSM {
				log.Enforcer = "BPFLSM"
			}
		}
	}

	if log.Source == "" {
		// even if a log doesn't have a source, it must have a type
		if log.Type == "" {
			if strings.Contains(log.Enforcer, "PRESET") {
				kg.Printf("no source and type: %s\n", log.Enforcer)
			}
			return
		}
		fd.Debug("Pushing Telemetry without source")
	}

	// set hostname
	log.HostName = cfg.GlobalCfg.Host

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
	if log.Type == "MatchedPolicy" || log.Type == "MatchedHostPolicy" || log.Type == "SystemEvent" {

		// checking throttling condition for "Audit" alerts when enforcer is 'eBPF Monitor'
		if cfg.GlobalCfg.AlertThrottling && ((strings.Contains(log.Action, "Audit") && log.Enforcer == "eBPF Monitor") || (log.Type == "MatchedHostPolicy" && (log.Enforcer == "AppArmor" || log.Enforcer == "eBPF Monitor"))) {
			nsKey := fd.ContainerNsKey[log.ContainerID]
			alert, throttle := fd.ShouldDropAlertsPerContainer(nsKey.PidNs, nsKey.MntNs)
			if alert && throttle {
				return
			} else if alert && !throttle {
				log.Operation = "AlertThreshold"
				log.Type = "SystemEvent"
				log.MaxAlertsPerSec = cfg.GlobalCfg.MaxAlertPerSec
				log.DroppingAlertsInterval = cfg.GlobalCfg.ThrottleSec
			}
		}
		pbAlert := pb.Alert{}

		node := fd.GetNodeInfo()

		pbAlert.KubeArmorVersion = log.KubeArmorVersion

		pbAlert.Timestamp = log.Timestamp
		pbAlert.UpdatedTime = log.UpdatedTime

		pbAlert.ClusterName = cfg.GlobalCfg.Cluster
		pbAlert.HostName = node.NodeName
		pbAlert.NodeID = node.NodeID

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

		if len(log.Severity) > 0 && log.Severity != "0" {
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
		pbAlert.TTY = log.TTY
		pbAlert.Source = log.Source
		pbAlert.Operation = log.Operation
		pbAlert.Resource = strings.ToValidUTF8(log.Resource, "")
		pbAlert.Cwd = log.Cwd

		pbAlert.ExecEvent = &pb.ExecEvent{
			ExecID:         log.ExecEvent.ExecID,
			ExecutableName: log.ExecEvent.ExecutableName,
		}

		if len(log.Data) > 0 {
			pbAlert.Data = log.Data
		}
		pbAlert.ProcessHash = log.ProcessHash[:]
		pbAlert.ParentHash = log.ParentHash[:]
		pbAlert.ResourceHash = log.ResourceHash[:]
		if len(log.HashAlgo) > 0 {
			pbAlert.HashAlgo = log.HashAlgo
		}

		if len(log.Action) > 0 {
			pbAlert.Action = log.Action
		}

		pbAlert.Result = log.Result
		pbAlert.MaxAlertsPerSec = log.MaxAlertsPerSec
		pbAlert.DroppingAlertsInterval = log.DroppingAlertsInterval

		fd.EventStructs.AlertLock.Lock()
		defer fd.EventStructs.AlertLock.Unlock()
		counter := 0
		lenAlert := len(fd.EventStructs.AlertStructs)

		for uid := range fd.EventStructs.AlertStructs {
			select {
			case fd.EventStructs.AlertStructs[uid].Broadcast <- &pbAlert:
			default:
				counter++
				if counter == lenAlert {
					//Default on the last uid in Alterstruct means the Alert isnt pushed into Broadcast
					kg.Printf("log channel busy, alert dropped.")
				}

			}
		}

		// Increment alert metric
		nodeName := cfg.GlobalCfg.Host
		AlertsTotal.WithLabelValues(nodeName).Inc()
	} else { // ContainerLog || HostLog
		pbLog := pb.Log{}
		node := fd.GetNodeInfo()

		pbLog.Timestamp = log.Timestamp
		pbLog.UpdatedTime = log.UpdatedTime

		pbLog.ClusterName = cfg.GlobalCfg.Cluster

		pbLog.HostName = node.NodeName
		pbLog.NodeID = node.NodeID

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
		pbLog.TTY = log.TTY
		pbLog.Source = log.Source
		pbLog.Operation = log.Operation
		pbLog.Resource = strings.ToValidUTF8(log.Resource, "")
		pbLog.Cwd = log.Cwd

		pbLog.ExecEvent = &pb.ExecEvent{
			ExecID:         log.ExecEvent.ExecID,
			ExecutableName: log.ExecEvent.ExecutableName,
		}

		if len(log.Data) > 0 {
			pbLog.Data = log.Data
		}
		pbLog.ProcessHash = log.ProcessHash[:]
		pbLog.ParentHash = log.ParentHash[:]
		pbLog.ResourceHash = log.ResourceHash[:]
		if len(log.HashAlgo) > 0 {
			pbLog.HashAlgo = log.HashAlgo
		}

		pbLog.Result = log.Result

		fd.EventStructs.LogLock.Lock()
		defer fd.EventStructs.LogLock.Unlock()
		counter := 0
		lenlog := len(fd.EventStructs.LogStructs)
		for uid := range fd.EventStructs.LogStructs {
			select {
			case fd.EventStructs.LogStructs[uid].Broadcast <- &pbLog:
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

func loadTLSCredentials(ip string) (credentials.TransportCredentials, error) {
	// create certificate configurations
	serverCertConfig := cert.DefaultKubeArmorServerConfig
	serverCertConfig.IPs = []string{ip}
	serverCertConfig.NotAfter = time.Now().Add(365 * 24 * time.Hour) //valid for 1 year
	// as of now daemonset creates certificates dynamically
	tlsConfig := cert.TlsConfig{
		CertCfg:      serverCertConfig,
		CertProvider: cfg.GlobalCfg.TLSCertProvider,
		CACertPath:   cert.GetCACertPath(config.GlobalCfg.TLSCertPath),
	}
	creds, err := cert.NewTlsCredentialManager(&tlsConfig).CreateTlsServerCredentials()
	return creds, err
}

func (fd *Feeder) ShouldDropAlertsPerContainer(pidNs, mntNs uint32) (bool, bool) {
	currentTimestamp := kl.GetCurrentTimeStamp()

	key := OuterKey{
		PidNs: pidNs,
		MntNs: mntNs,
	}

	if fd.AlertMap == nil {
		fd.AlertMap = make(map[OuterKey]AlertThrottleState)
	}

	state, ok := fd.AlertMap[key]

	if !ok {
		newState := AlertThrottleState{
			EventCount:          1,
			FirstEventTimestamp: currentTimestamp,
			Throttle:            false,
		}
		fd.AlertMap[key] = newState
		return false, false
	}

	throttleSec := uint64(cfg.GlobalCfg.ThrottleSec) * 1000000000 // Throttle duration in nanoseconds
	maxAlertPerSec := uint64(cfg.GlobalCfg.MaxAlertPerSec)

	if state.Throttle {
		timeDifference := currentTimestamp - state.FirstEventTimestamp
		if timeDifference < throttleSec {
			return true, true
		}
	}

	timeDifference := currentTimestamp - state.FirstEventTimestamp

	if timeDifference >= 1000000000 { // 1 second
		state.FirstEventTimestamp = currentTimestamp
		state.EventCount = 1
		state.Throttle = false
	} else {
		state.EventCount++
	}

	if state.EventCount > maxAlertPerSec {
		state.EventCount = 0
		state.Throttle = true
		fd.AlertMap[key] = state
		return true, false
	}

	fd.AlertMap[key] = state
	return false, false
}

func (fd *Feeder) DeleteAlertMapKey(outkey kl.OuterKey) {
	delete(fd.AlertMap, OuterKey{PidNs: outkey.PidNs, MntNs: outkey.MntNs})
}
func (fd *Feeder) GetEnforcer() string {
	fd.EnforcerLock.RLock()
	val := fd.Enforcer
	fd.EnforcerLock.RUnlock()
	return val
}
func (fd *Feeder) GetNodeInfo() tp.Node {
	lock := *fd.NodeLock
	lock.RLock()
	defer lock.RUnlock()

	node := *fd.Node
	return node
}
