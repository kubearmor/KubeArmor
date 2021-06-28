package core

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	pb "github.com/accuknox/KubeArmor/protobuf"
	"github.com/google/uuid"
	"google.golang.org/grpc"

	v1 "k8s.io/api/core/v1"
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

	MsgQueue = make(chan pb.Message, 2048)
	AlertQueue = make(chan pb.Alert, 8192)
	LogQueue = make(chan pb.Log, 65536)
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
	MsgLock    sync.Mutex

	AlertStructs map[string]AlertStruct
	AlertLock    sync.Mutex

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
		msg := <-MsgQueue

		msgStructs := ls.getMsgStructs()
		for _, mgs := range msgStructs {
			mgs.Client.Send(&msg)
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
		alert := <-AlertQueue

		alertStructs := ls.getAlertStructs()
		for _, als := range alertStructs {
			als.Client.Send(&alert)
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
		log := <-LogQueue

		logStructs := ls.getLogStructs()
		for _, lgs := range logStructs {
			lgs.Client.Send(&log)
		}
	}

	return nil
}

// ================== //
// == Relay Server == //
// ================== //

// RelayServer Structure
type RelayServer struct {
	// port
	Port string

	// gRPC listener
	Listener net.Listener

	// log server
	LogServer *grpc.Server

	// client list
	ClientList map[string]*LogClient

	// wait group
	WgServer sync.WaitGroup
}

// K8sPodEvent Structure
type K8sPodEvent struct {
	Type   string `json:"type"`
	Object v1.Pod `json:"object"`
}

// NewRelayServer Function
func NewRelayServer(port string) *RelayServer {
	rs := &RelayServer{}

	rs.Port = port

	// listen to gRPC port
	listener, err := net.Listen("tcp", ":"+rs.Port)
	if err != nil {
		fmt.Printf("Failed to listen a port (%s)\n", rs.Port)
		fmt.Println(err.Error())
		return nil
	}
	rs.Listener = listener

	// create a log server
	rs.LogServer = grpc.NewServer()

	// register a log service
	logService := &LogService{
		MsgStructs:   make(map[string]MsgStruct),
		MsgLock:      sync.Mutex{},
		AlertStructs: make(map[string]AlertStruct),
		AlertLock:    sync.Mutex{},
		LogStructs:   make(map[string]LogStruct),
		LogLock:      sync.Mutex{},
	}
	pb.RegisterLogServiceServer(rs.LogServer, logService)

	// reset a client list
	rs.ClientList = map[string]*LogClient{}

	// set wait group
	rs.WgServer = sync.WaitGroup{}

	return rs
}

// ServeLogFeeds Function
func (rs *RelayServer) ServeLogFeeds() {
	rs.WgServer.Add(1)
	defer rs.WgServer.Done()

	// feed logs
	rs.LogServer.Serve(rs.Listener)
}

// GetFeedsFromNodes Function
func (rs *RelayServer) GetFeedsFromNodes() {
	if K8s.InitK8sClient() {
		fmt.Println("Initialized the Kubernetes client")

		for Running {
			if resp := K8s.WatchK8sPods(); resp != nil {
				defer resp.Body.Close()

				decoder := json.NewDecoder(resp.Body)
				for Running {
					event := K8sPodEvent{}
					if err := decoder.Decode(&event); err == io.EOF {
						break
					} else if err != nil {
						break
					}

					if val, ok := event.Object.Labels["kubearmor-app"]; !ok {
						continue
					} else if val != "kubearmor" {
						continue
					}

					nodeIP := event.Object.Status.HostIP
					server := nodeIP + ":" + rs.Port

					if event.Type != "DELETED" {
						if oldClient, ok := rs.ClientList[nodeIP]; !ok {
							// create a client
							client := NewClient(server)
							if client == nil {
								fmt.Printf("Failed to connect to the gRPC server (%s)\n", server)
								continue
							}

							// do healthcheck
							if ok := client.DoHealthCheck(); !ok {
								fmt.Println("Failed to check the liveness of the gRPC server")
								return
							}
							fmt.Println("Checked the liveness of the gRPC server")

							// watch messages
							go client.WatchMessages()
							fmt.Println("Started to watch messages from " + server)

							// watch alerts
							go client.WatchAlerts()
							fmt.Println("Started to watch alerts from " + server)

							// watch logs
							go client.WatchLogs()
							fmt.Println("Started to watch logs from " + server)

							rs.ClientList[nodeIP] = client
						} else {
							// do healthcheck
							if ok := oldClient.DoHealthCheck(); ok {
								continue
							}

							if err := oldClient.DestroyClient(); err != nil {
								fmt.Printf("Failed to destroy the gRPC client (%s)\n", server)
							}

							fmt.Printf("Try to reconnect to the gRPC server (%s)\n", server)

							// create a client
							client := NewClient(server)
							if client == nil {
								fmt.Printf("Failed to reconnect to the gRPC server (%s)\n", server)
								continue
							}

							// do healthcheck
							if ok := client.DoHealthCheck(); !ok {
								fmt.Println("Failed to check the liveness of the gRPC server")
								return
							}
							fmt.Println("Checked the liveness of the gRPC server")

							// watch messages
							go client.WatchMessages()
							fmt.Println("Started to watch messages from " + server)

							// watch alerts
							go client.WatchAlerts()
							fmt.Println("Started to watch alerts from " + server)

							// watch logs
							go client.WatchLogs()
							fmt.Println("Started to watch logs from " + server)

							rs.ClientList[nodeIP] = client
						}

					} else {
						if val, ok := rs.ClientList[nodeIP]; !ok {
							// destroy the client
							if err := val.DestroyClient(); err != nil {
								fmt.Printf("Failed to destroy the gRPC client (%s)\n", server)
							}

							delete(rs.ClientList, nodeIP)
						}
					}
				}
			} else {
				time.Sleep(time.Second * 1)
			}
		}
	}
}

// DestroyRelayServer Function
func (rs *RelayServer) DestroyRelayServer() error {
	// stop gRPC service
	Running = false

	// wait for a while
	time.Sleep(time.Second * 1)

	// close listener
	if rs.Listener != nil {
		rs.Listener.Close()
		rs.Listener = nil
	}

	// wait for other routines
	rs.WgServer.Wait()

	return nil
}
