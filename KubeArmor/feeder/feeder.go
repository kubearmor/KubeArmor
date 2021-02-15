package feeder

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	kl "github.com/accuknox/KubeArmor/KubeArmor/common"
	kg "github.com/accuknox/KubeArmor/KubeArmor/log"
	tp "github.com/accuknox/KubeArmor/KubeArmor/types"

	pb "github.com/accuknox/KubeArmor/protobuf"
	"github.com/google/uuid"
	"google.golang.org/grpc"
)

// ============ //
// == Global == //
// ============ //

// Running flag
var Running bool

// MsgQueue for Messages
var MsgQueue []pb.Message

// MsgLock for Messages
var MsgLock sync.Mutex

// Stats for Statistics
var Stats tp.StatsType

// StatQueue for Statistics
var StatQueue []pb.Stats

// StatLock for Statistics
var StatLock sync.Mutex

// LogQueue for Logs
var LogQueue []pb.Log

// LogLock for Logs
var LogLock sync.Mutex

func init() {
	Running = true

	MsgQueue = []pb.Message{}
	MsgLock = sync.Mutex{}

	Stats = tp.StatsType{}
	Stats.HostStats = tp.HostStatType{HostName: kl.GetHostName()}
	Stats.NamespaceStats = map[string]tp.NamespaceStatType{}
	Stats.PodStats = map[string]tp.PodStatType{}
	Stats.ContainerStats = map[string]tp.ContainerStatType{}

	StatQueue = []pb.Stats{}
	StatLock = sync.Mutex{}

	LogQueue = []pb.Log{}
	LogLock = sync.Mutex{}
}

// ========== //
// == gRPC == //
// ========== //

// MsgStruct Structure
type MsgStruct struct {
	Client pb.LogService_WatchMessagesServer
	Filter string
}

// StatStruct Structure
type StatStruct struct {
	Client pb.LogService_WatchStatisticsServer
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
	MsgLock    sync.Mutex

	StatStructs map[string]StatStruct
	StatLock    sync.Mutex

	LogStructs map[string]LogStruct
	LogLock    sync.Mutex
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
		MsgLock.Lock()

		msgStructs := ls.getMsgStructs()

		for len(MsgQueue) != 0 {
			msg := MsgQueue[0]
			MsgQueue = MsgQueue[1:]

			for _, mgs := range msgStructs {
				mgs.Client.Send(&msg)
			}
		}

		MsgLock.Unlock()

		time.Sleep(time.Millisecond * 1)
	}

	return nil
}

// addStatStruct Function
func (ls *LogService) addStatStruct(uid string, srv pb.LogService_WatchStatisticsServer, filter string) {
	ls.MsgLock.Lock()
	defer ls.MsgLock.Unlock()

	statStruct := StatStruct{}
	statStruct.Client = srv
	statStruct.Filter = filter

	ls.StatStructs[uid] = statStruct
}

// removeStatStruct Function
func (ls *LogService) removeStatStruct(uid string) {
	ls.StatLock.Lock()
	defer ls.StatLock.Unlock()

	delete(ls.StatStructs, uid)
}

// getStatStructs Function
func (ls *LogService) getStatStructs() []StatStruct {
	statStructs := []StatStruct{}

	ls.StatLock.Lock()
	defer ls.StatLock.Unlock()

	for _, sts := range ls.StatStructs {
		statStructs = append(statStructs, sts)
	}

	return statStructs
}

// WatchStatistics Function
func (ls *LogService) WatchStatistics(req *pb.RequestMessage, svr pb.LogService_WatchStatisticsServer) error {
	uid := uuid.Must(uuid.NewRandom()).String()

	ls.addStatStruct(uid, svr, req.Filter)
	defer ls.removeStatStruct(uid)

	for Running {
		StatLock.Lock()

		statStructs := ls.getStatStructs()

		for len(StatQueue) != 0 {
			stat := StatQueue[0]
			StatQueue = StatQueue[1:]

			for _, sts := range statStructs {
				sts.Client.Send(&stat)
			}
		}

		StatLock.Unlock()

		time.Sleep(time.Millisecond * 1)
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
		LogLock.Lock()

		logStructs := ls.getLogStructs()

		for len(LogQueue) != 0 {
			log := LogQueue[0]
			LogQueue = LogQueue[1:]

			for _, lgs := range logStructs {
				if lgs.Filter == "" {
					lgs.Client.Send(&log)
				} else if lgs.Filter == "policy" && log.Type == "PolicyMatched" {
					lgs.Client.Send(&log)
				} else if lgs.Filter == "system" && log.Type == "SystemLog" {
					lgs.Client.Send(&log)
				}
			}
		}

		LogLock.Unlock()

		time.Sleep(time.Millisecond * 1)
	}

	return nil
}

// ============ //
// == Feeder == //
// ============ //

// Feeder Structure
type Feeder struct {
	// port
	port string

	// output
	output string

	// gRPC listener
	listener net.Listener

	// log server
	logServer *grpc.Server

	// wait group
	WgServer sync.WaitGroup

	// ticker
	TickCount   int
	StatsTicker *time.Ticker

	// host
	hostName string
	hostIP   string
}

// NewFeeder Function
func NewFeeder(port, output string) *Feeder {
	fd := &Feeder{}

	fd.port = fmt.Sprintf(":%s", port)
	fd.output = output

	// output mode
	if fd.output != "stdout" && fd.output != "none" {
		// get the directory part from the path
		dirLog := filepath.Dir(fd.output)

		// create directories
		if err := os.MkdirAll(dirLog, 0755); err != nil {
			kg.Errf("Failed to create a target directory (%s, %s)", dirLog, err.Error())
			return nil
		}

		// create target file
		targetFile, err := os.Create(fd.output)
		if err != nil {
			kg.Errf("Failed to create a target file (%s, %s)", fd.output, err.Error())
			return nil
		}
		targetFile.Close()
	}

	// listen to gRPC port
	listener, err := net.Listen("tcp", fd.port)
	if err != nil {
		kg.Errf("Failed to listen a port (%s, %s)", port, err.Error())
		return nil
	}
	fd.listener = listener

	// create a log server
	fd.logServer = grpc.NewServer()

	// register a log service
	logService := &LogService{
		MsgStructs:  make(map[string]MsgStruct),
		MsgLock:     sync.Mutex{},
		StatStructs: make(map[string]StatStruct),
		StatLock:    sync.Mutex{},
		LogStructs:  make(map[string]LogStruct),
		LogLock:     sync.Mutex{},
	}
	pb.RegisterLogServiceServer(fd.logServer, logService)

	// set wait group
	fd.WgServer = sync.WaitGroup{}

	// set ticker
	fd.StatsTicker = time.NewTicker(time.Second * 10)

	go fd.PushStatistics()

	// set host info
	fd.hostName = kl.GetHostName()
	fd.hostIP = kl.GetExternalIPAddr()

	return fd
}

// DestroyFeeder Function
func (fd *Feeder) DestroyFeeder() error {
	// stop gRPC service
	Running = false

	// stop ticker
	fd.StatsTicker.Stop()

	// wait for a while
	time.Sleep(time.Second * 1)

	// close listener
	if fd.listener != nil {
		fd.listener.Close()
		fd.listener = nil
	}

	// wait for other routines
	fd.WgServer.Wait()

	return nil
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

// ================ //
// == Statistics == //
// ================ //

// AddContainerInfo Function
func (fd *Feeder) AddContainerInfo(container tp.Container) {
	StatLock.Lock()
	defer StatLock.Unlock()

	if _, ok := Stats.NamespaceStats[container.NamespaceName]; !ok {
		nStat := tp.NamespaceStatType{}

		nStat.HostName = container.HostName
		nStat.NamespaceName = container.NamespaceName

		nStat.Containers = []string{container.ContainerID}

		Stats.NamespaceStats[container.NamespaceName] = nStat
	} else {
		nStat := Stats.NamespaceStats[container.NamespaceName]
		nStat.Containers = append(nStat.Containers, container.ContainerID)
		Stats.NamespaceStats[container.NamespaceName] = nStat
	}

	podName := container.NamespaceName + "_" + container.ContainerGroupName

	if _, ok := Stats.PodStats[podName]; !ok {
		pStat := tp.PodStatType{}

		pStat.HostName = container.HostName
		pStat.NamespaceName = container.NamespaceName
		pStat.PodName = container.ContainerGroupName

		pStat.Containers = []string{container.ContainerID}

		Stats.PodStats[podName] = pStat
	} else {
		pStat := Stats.PodStats[podName]
		pStat.Containers = append(pStat.Containers, container.ContainerID)
		Stats.PodStats[podName] = pStat
	}

	if _, ok := Stats.ContainerStats[container.ContainerID]; !ok {
		cStat := tp.ContainerStatType{}

		cStat.HostName = container.HostName
		cStat.NamespaceName = container.NamespaceName
		cStat.PodName = container.ContainerGroupName
		cStat.ContainerName = container.ContainerName

		Stats.ContainerStats[container.ContainerID] = cStat
	}
}

// RemoveContainerInfo Function
func (fd *Feeder) RemoveContainerInfo(container tp.Container) {
	StatLock.Lock()
	defer StatLock.Unlock()

	if len(Stats.NamespaceStats[container.NamespaceName].Containers) == 1 {
		delete(Stats.NamespaceStats, container.NamespaceName)
	} else {
		nStat := Stats.NamespaceStats[container.NamespaceName]
		for idx, id := range nStat.Containers {
			if id == container.ContainerID {
				nStat.Containers = append(nStat.Containers[:idx], nStat.Containers[idx+1:]...)
				break
			}
		}
		Stats.NamespaceStats[container.NamespaceName] = nStat
	}

	podName := container.NamespaceName + "_" + container.ContainerGroupName

	if len(Stats.PodStats[podName].Containers) == 1 {
		delete(Stats.PodStats, podName)
	} else {
		pStat := Stats.PodStats[podName]
		for idx, id := range pStat.Containers {
			if id == container.ContainerID {
				pStat.Containers = append(pStat.Containers[:idx], pStat.Containers[idx+1:]...)
				break
			}
		}
		Stats.PodStats[podName] = pStat
	}

	delete(Stats.ContainerStats, container.ContainerID)
}

// UpdateStatistics Function
func (fd *Feeder) UpdateStatistics(log tp.Log) {
	StatLock.Lock()
	defer StatLock.Unlock()

	if log.ContainerName == "" {
		return
	}

	if log.PolicyName != "" { // PolicyMatched
		if (log.Action == "Allow" || log.Action == "AllowWithAudit") && log.Result == "Passed" {
			Stats.HostStats.AllowedCount++

			nStat := Stats.NamespaceStats[log.NamespaceName]
			nStat.AllowedCount++
			Stats.NamespaceStats[log.NamespaceName] = nStat

			pStat := Stats.PodStats[log.NamespaceName+"_"+log.PodName]
			pStat.AllowedCount++
			Stats.PodStats[log.NamespaceName+"_"+log.PodName] = pStat

			cStat := Stats.ContainerStats[log.ContainerID]
			cStat.AllowedCount++
			Stats.ContainerStats[log.ContainerID] = cStat
		} else if log.Action == "Audit" && log.Result == "Passed" {
			Stats.HostStats.AuditedCount++

			nStat := Stats.NamespaceStats[log.NamespaceName]
			nStat.AuditedCount++
			Stats.NamespaceStats[log.NamespaceName] = nStat

			pStat := Stats.PodStats[log.NamespaceName+"_"+log.PodName]
			pStat.AuditedCount++
			Stats.PodStats[log.NamespaceName+"_"+log.PodName] = pStat

			cStat := Stats.ContainerStats[log.ContainerID]
			cStat.AuditedCount++
			Stats.ContainerStats[log.ContainerID] = cStat
		} else { // Block
			Stats.HostStats.BlockedCount++

			nStat := Stats.NamespaceStats[log.NamespaceName]
			nStat.BlockedCount++
			Stats.NamespaceStats[log.NamespaceName] = nStat

			pStat := Stats.PodStats[log.NamespaceName+"_"+log.PodName]
			pStat.BlockedCount++
			Stats.PodStats[log.NamespaceName+"_"+log.PodName] = pStat

			cStat := Stats.ContainerStats[log.ContainerID]
			cStat.BlockedCount++
			Stats.ContainerStats[log.ContainerID] = cStat
		}
	} else { // SystemLog
		Stats.HostStats.FailedCount++

		nStat := Stats.NamespaceStats[log.NamespaceName]
		nStat.FailedCount++
		Stats.NamespaceStats[log.NamespaceName] = nStat

		pStat := Stats.PodStats[log.NamespaceName+"_"+log.PodName]
		pStat.FailedCount++
		Stats.PodStats[log.NamespaceName+"_"+log.PodName] = pStat

		cStat := Stats.ContainerStats[log.ContainerID]
		cStat.FailedCount++
		Stats.ContainerStats[log.ContainerID] = cStat
	}
}

// PushStatistics Function
func (fd *Feeder) PushStatistics() {
	for range fd.StatsTicker.C {
		StatLock.Lock()

		pbStats := pb.Stats{}

		pbStats.UpdatedTime = kl.GetDateTimeNow()

		hostStats := pb.HostStatType{}

		hostStats.HostName = Stats.HostStats.HostName

		hostStats.AllowedCount = Stats.HostStats.AllowedCount
		hostStats.AuditedCount = Stats.HostStats.AuditedCount
		hostStats.BlockedCount = Stats.HostStats.BlockedCount
		hostStats.FailedCount = Stats.HostStats.FailedCount

		Stats.HostStats.AllowedCount = 0
		Stats.HostStats.AuditedCount = 0
		Stats.HostStats.BlockedCount = 0
		Stats.HostStats.FailedCount = 0

		pbStats.HostStats = &hostStats

		namespaceStats := []*pb.NamespaceStatType{}

		for namespaceName := range Stats.NamespaceStats {
			stats := pb.NamespaceStatType{}

			nStats := Stats.NamespaceStats[namespaceName]

			stats.HostName = nStats.HostName
			stats.NamespaceName = nStats.NamespaceName

			stats.AllowedCount = nStats.AllowedCount
			stats.AuditedCount = nStats.AuditedCount
			stats.BlockedCount = nStats.BlockedCount
			stats.FailedCount = nStats.FailedCount

			nStats.AllowedCount = 0
			nStats.AuditedCount = 0
			nStats.BlockedCount = 0
			nStats.FailedCount = 0

			Stats.NamespaceStats[namespaceName] = nStats

			namespaceStats = append(namespaceStats, &stats)
		}

		pbStats.NamespaceStats = namespaceStats

		podStats := []*pb.PodStatType{}

		for nsPodName := range Stats.PodStats {
			stats := pb.PodStatType{}

			pStats := Stats.PodStats[nsPodName]

			stats.HostName = pStats.HostName
			stats.NamespaceName = pStats.NamespaceName
			stats.PodName = pStats.PodName

			stats.AllowedCount = pStats.AllowedCount
			stats.AuditedCount = pStats.AuditedCount
			stats.BlockedCount = pStats.BlockedCount
			stats.FailedCount = pStats.FailedCount

			pStats.AllowedCount = 0
			pStats.AuditedCount = 0
			pStats.BlockedCount = 0
			pStats.FailedCount = 0

			Stats.PodStats[nsPodName] = pStats

			podStats = append(podStats, &stats)
		}

		pbStats.PodStats = podStats

		containerStats := []*pb.ContainerStatType{}

		for containerID := range Stats.ContainerStats {
			stats := pb.ContainerStatType{}

			cStats := Stats.ContainerStats[containerID]

			stats.HostName = cStats.HostName
			stats.NamespaceName = cStats.NamespaceName
			stats.PodName = cStats.PodName
			stats.ContainerName = cStats.ContainerName

			stats.AllowedCount = cStats.AllowedCount
			stats.AuditedCount = cStats.AuditedCount
			stats.BlockedCount = cStats.BlockedCount
			stats.FailedCount = cStats.FailedCount

			cStats.AllowedCount = 0
			cStats.AuditedCount = 0
			cStats.BlockedCount = 0
			cStats.FailedCount = 0

			Stats.ContainerStats[containerID] = cStats

			containerStats = append(containerStats, &stats)
		}

		pbStats.ContainerStats = containerStats

		StatQueue = append(StatQueue, pbStats)

		StatLock.Unlock()
	}
}

// =============== //
// == Log Feeds == //
// =============== //

// ServeLogFeeds Function
func (fd *Feeder) ServeLogFeeds() {
	fd.WgServer.Add(1)
	defer fd.WgServer.Done()

	// feed logs
	fd.logServer.Serve(fd.listener)
}

// PushMessage Function
func (fd *Feeder) PushMessage(level, message string) error {
	pbMsg := pb.Message{}

	pbMsg.UpdatedTime = kl.GetDateTimeNow()

	pbMsg.Source = fd.hostName
	pbMsg.SourceIP = fd.hostIP

	pbMsg.Level = level
	pbMsg.Message = message

	MsgLock.Lock()
	MsgQueue = append(MsgQueue, pbMsg)
	MsgLock.Unlock()

	return nil
}

// PushLog Function
func (fd *Feeder) PushLog(log tp.Log) error {
	if log.UpdatedTime == "" {
		return nil
	}

	pbLog := pb.Log{}

	pbLog.UpdatedTime = log.UpdatedTime

	pbLog.HostName = log.HostName

	pbLog.NamespaceName = log.NamespaceName
	pbLog.PodName = log.PodName
	pbLog.ContainerID = log.ContainerID
	pbLog.ContainerName = log.ContainerName

	pbLog.HostPID = log.HostPID
	pbLog.PPID = log.PPID
	pbLog.PID = log.PID
	pbLog.UID = log.UID

	if len(log.PolicyName) > 0 {
		pbLog.PolicyName = log.PolicyName
	}

	if len(log.Severity) > 0 {
		pbLog.Severity = log.Severity
	}

	pbLog.Type = log.Type
	pbLog.Source = log.Source
	pbLog.Operation = log.Operation
	pbLog.Resource = log.Resource

	if len(log.Data) > 0 {
		pbLog.Data = log.Data
	}

	if len(log.Action) > 0 {
		pbLog.Action = log.Action
	}

	pbLog.Result = log.Result

	LogLock.Lock()
	LogQueue = append(LogQueue, pbLog)
	LogLock.Unlock()

	fd.UpdateStatistics(log)

	if fd.output == "stdout" {
		arr, _ := json.Marshal(log)
		fmt.Println(string(arr))
	} else if fd.output != "none" {
		arr, _ := json.Marshal(log)
		kl.StrToFile(string(arr), fd.output)
	}

	return nil
}
