// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

// Package server exports kubearmor logs
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	pb "github.com/kubearmor/KubeArmor/protobuf"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"

	cfg "github.com/kubearmor/KubeArmor/pkg/KubeArmorRelayServer/config"
	"github.com/kubearmor/KubeArmor/pkg/KubeArmorRelayServer/elasticsearch"
	kg "github.com/kubearmor/KubeArmor/pkg/KubeArmorRelayServer/log"
	"github.com/kubearmor/KubeArmor/pkg/KubeArmorRelayServer/opensearch"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/tools/cache"
)

// ============ //
// == Global == //
// ============ //

// Running flag
var Running bool

// ClientList Map
var ClientList map[string]int

// ClientListLock Lock
var ClientListLock *sync.RWMutex

func init() {
	Running = true
	ClientList = map[string]int{}
	ClientListLock = &sync.RWMutex{}
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

// IP to K8sResource Map
var Ipcache sync.Map

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
	conn := make(chan *pb.Message, 1000)
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
					kg.Warnf("relay failed to send a message=[%+v] err=[%s]", resp, status.Err().Error())
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
	conn := make(chan *pb.Alert, 1000)
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
					kg.Warnf("relay failed to send an alert=[%+v] err=[%s]", resp, status.Err().Error())
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
	conn := make(chan *pb.Log, 10000)
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
					kg.Warnf("relay failed to send a log=[%+v] err=[%s]", resp, status.Err().Error())
					return status.Err()
				default:
					return nil
				}
			}
		}
	}

	return nil
}

// =============== //
// == Log Feeds == //
// =============== //

// LogClient Structure
type LogClient struct {
	// flag
	Running bool

	// Server
	Server string

	// connection
	conn *grpc.ClientConn

	// client
	client pb.LogServiceClient

	// messages
	MsgStream pb.LogService_WatchMessagesClient

	// alerts
	AlertStream pb.LogService_WatchAlertsClient

	// logs
	LogStream pb.LogService_WatchLogsClient

	// wait group
	WgServer *errgroup.Group

	Context context.Context
}

// NewClient Function
func NewClient(server string) *LogClient {
	var err error

	lc := &LogClient{}

	lc.Running = true

	// == //

	lc.Server = server
	var creds credentials.TransportCredentials
	if cfg.GlobalConfig.TLSEnabled {
		creds, err = loadTLSClientCredentials()
		if err != nil {
			kg.Errf("cannot load TLS credentials: ", err)
			return nil
		}
	} else {
		creds = insecure.NewCredentials()
	}

	lc.conn, err = grpc.Dial(lc.Server, grpc.WithTransportCredentials(creds))
	if err != nil {
		kg.Warnf("Failed to connect to KubeArmor's gRPC service (%s)", server)
		return nil
	}
	defer func() {
		if err != nil {
			err = lc.DestroyClient()
			if err != nil {
				kg.Warnf("DestroyClient() failed err=%s", err.Error())
			}
		}
	}()

	lc.client = pb.NewLogServiceClient(lc.conn)

	// == //

	msgIn := pb.RequestMessage{}
	msgIn.Filter = "all"

	lc.MsgStream, err = lc.client.WatchMessages(context.Background(), &msgIn)
	if err != nil {
		kg.Warnf("Failed to call WatchMessages (%s) err=%s\n", server, err.Error())
		return nil
	}

	// == //

	alertIn := pb.RequestMessage{}
	alertIn.Filter = "policy"

	lc.AlertStream, err = lc.client.WatchAlerts(context.Background(), &alertIn)
	if err != nil {
		kg.Warnf("Failed to call WatchAlerts (%s) err=%s\n", server, err.Error())
		return nil
	}

	// == //

	logIn := pb.RequestMessage{}
	logIn.Filter = "system"

	lc.LogStream, err = lc.client.WatchLogs(context.Background(), &logIn)
	if err != nil {
		kg.Warnf("Failed to call WatchLogs (%s)\n err=%s", server, err.Error())
		return nil
	}

	return lc
}

// DoHealthCheck Function
func DoHealthCheck(nodeIP string) bool {
	healthServer := net.JoinHostPort(nodeIP, cfg.GlobalConfig.LivenessPort)

	// Liveness probe port doesn't use TLS
	conn, err := grpc.NewClient(healthServer, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		kg.Warnf("Failed to connect to KubeArmor's health check service (%s)", healthServer)
		return false
	}
	defer conn.Close()

	// KubeArmor serves on the liveness probe port 32766
	client := grpc_health_v1.NewHealthClient(conn)
	res, err := client.Check(context.Background(), &grpc_health_v1.HealthCheckRequest{})
	if err != nil {
		kg.Warnf("Failed to check the liveness of KubeArmor's gRPC service (%s) %v", healthServer, err)
		return false
	}

	return res.Status == grpc_health_v1.HealthCheckResponse_SERVING
}

// WatchMessages Function
func (lc *LogClient) WatchMessages(wg *sync.WaitGroup, stop chan struct{}, errCh chan error) {

	defer wg.Done()
	var err error

	for lc.Running {
		var res *pb.Message

		select {
		case <-stop:
			return
		default:
			if res, err = lc.MsgStream.Recv(); err != nil {
				errCh <- fmt.Errorf("failed to receive a message (%s) %s", lc.Server, err.Error())
				return
			}

			select {
			case MsgBufferChannel <- res:
			case <-stop:
				return
			default:
				// Not able to add it to Message buffer
			}
		}
	}

	kg.Print("Stopped watching messages from " + lc.Server)
}

// AddMsgFromBuffChan Adds Msg from MsgBufferChannel into MsgStructs
func (rs *RelayServer) AddMsgFromBuffChan() {

	for Running {
		select {
		case msg := <-MsgBufferChannel:
			if stdoutmsg {
				tel, _ := json.Marshal(msg)
				fmt.Printf("%s\n", string(tel))
			}
			MsgLock.RLock()
			for uid := range MsgStructs {
				select {
				case MsgStructs[uid].Broadcast <- msg:
				default:
				}
			}
			MsgLock.RUnlock()

		default:
			time.Sleep(time.Millisecond * 10)
		}

	}
}

// WatchAlerts Function
func (lc *LogClient) WatchAlerts(wg *sync.WaitGroup, stop chan struct{}, errCh chan error) {

	defer wg.Done()

	var err error

	for lc.Running {
		var res *pb.Alert

		select {
		case <-stop:
			return
		default:
			if res, err = lc.AlertStream.Recv(); err != nil {
				errCh <- fmt.Errorf("failed to receive an alert (%s) %s", lc.Server, err.Error())
				return
			}

			select {
			case AlertBufferChannel <- res:
			case <-stop:
				return
			default:
				// Not able to add it to Alert buffer
			}
		}
	}

	kg.Print("Stopped watching alerts from " + lc.Server)
}

// AddAlertFromBuffChan Adds Alert from AlertBufferChannel into AlertStructs
func (rs *RelayServer) AddAlertFromBuffChan() {

	for Running {
		select {
		case alert := <-AlertBufferChannel:
			if stdoutalerts {
				tel, _ := json.Marshal(alert)
				fmt.Printf("%s\n", string(tel))
			}
			if rs.ELKClient != nil {
				rs.ELKClient.SendAlertToBuffer(alert)
			}
			if rs.OSClient != nil {
				rs.OSClient.SendTelemetryToBuffer(alert)
			}
			AlertLock.RLock()
			for uid := range AlertStructs {
				select {
				case AlertStructs[uid].Broadcast <- alert:
				default:
				}
			}
			AlertLock.RUnlock()

		default:
			time.Sleep(time.Millisecond * 10)
		}

	}
}

// WatchLogs Function
func (lc *LogClient) WatchLogs(wg *sync.WaitGroup, stop chan struct{}, errCh chan error) {
	defer wg.Done()

	var err error

	for lc.Running {
		var res *pb.Log

		select {
		case <-stop:
			return
		default:
			if res, err = lc.LogStream.Recv(); err != nil {
				errCh <- fmt.Errorf("failed to receive a log (%s) %s", lc.Server, err.Error())
				return
			}
			addRemoteHostInfo(res)

			select {
			case LogBufferChannel <- res:
			case <-stop:
				return
			default:
				// Not able to add it to Log buffer
			}
		}
	}

	kg.Print("Stopped watching logs from " + lc.Server)
}

// AddLogFromBuffChan Adds Log from LogBufferChannel into LogStructs
func (rs *RelayServer) AddLogFromBuffChan() {

	for Running {
		select {
		case log := <-LogBufferChannel:
			if stdoutlogs {
				tel, _ := json.Marshal(log)
				fmt.Printf("%s\n", string(tel))
			}

			if rs.OSClient != nil {
				rs.OSClient.SendTelemetryToBuffer(log)
			}
			for uid := range LogStructs {
				select {
				case LogStructs[uid].Broadcast <- log:
				default:
				}
			}
		default:
			time.Sleep(time.Millisecond * 10)
		}

	}
}

// DestroyClient Function
func (lc *LogClient) DestroyClient() error {
	lc.Running = false

	err := lc.conn.Close()

	return err
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

	// wait group
	WgServer sync.WaitGroup

	// ELK adapter
	ELKClient *elasticsearch.ElasticsearchClient

	// Opensearch Adapter
	OSClient *opensearch.OpenSearchClient
}

// LogBufferChannel store incoming data from log stream in buffer
var LogBufferChannel chan *pb.Log

// MsgBufferChannel store incoming data from Alert stream in buffer
var MsgBufferChannel chan *pb.Message

// AlertBufferChannel store incoming data from msg stream in buffer
var AlertBufferChannel chan *pb.Alert

// NewRelayServer Function
func NewRelayServer(port string) *RelayServer {
	rs := &RelayServer{}

	rs.Port = port

	LogBufferChannel = make(chan *pb.Log, 10000)
	AlertBufferChannel = make(chan *pb.Alert, 1000)
	MsgBufferChannel = make(chan *pb.Message, 100)

	// listen to gRPC port
	listener, err := net.Listen("tcp", ":"+rs.Port)
	if err != nil {
		kg.Errf("Failed to listen a port (%s)\n", rs.Port)
		return nil
	}
	rs.Listener = listener

	kaep := keepalive.EnforcementPolicy{
		PermitWithoutStream: true,
	}

	kasp := keepalive.ServerParameters{
		Time: 5 * time.Second,
	}

	// create a log server
	var creds credentials.TransportCredentials
	if cfg.GlobalConfig.TLSEnabled {
		creds, err = loadTLSServerCredentials()
		if err != nil {
			kg.Errf("cannot load TLS credentials: ", err)
			return nil
		}
		rs.LogServer = grpc.NewServer(grpc.Creds(creds), grpc.KeepaliveEnforcementPolicy(kaep), grpc.KeepaliveParams(kasp))
	} else {
		rs.LogServer = grpc.NewServer(grpc.KeepaliveEnforcementPolicy(kaep), grpc.KeepaliveParams(kasp))
	}

	// register a log service
	logService := &LogService{}
	pb.RegisterLogServiceServer(rs.LogServer, logService)

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
	rs.WgServer = sync.WaitGroup{}

	return rs
}

// DestroyRelayServer Function
func (rs *RelayServer) DestroyRelayServer() error {
	// stop gRPC service
	Running = false

	// wait for a while
	time.Sleep(time.Second * 1)

	// close listener
	if rs.Listener != nil {
		if err := rs.Listener.Close(); err != nil {
			kg.Err(err.Error())
		}
		rs.Listener = nil
	}

	// wait for other routines
	rs.WgServer.Wait()
	return nil
}

// =============== //
// == Log Feeds == //
// =============== //

// ServeLogFeeds Function
func (rs *RelayServer) ServeLogFeeds() {
	rs.WgServer.Add(1)
	defer rs.WgServer.Done()

	// feed logs
	if err := rs.LogServer.Serve(rs.Listener); err != nil {
		kg.Print("Terminated the gRPC service")
	}
}

// DeleteClientEntry removes nodeIP from ClientList
func DeleteClientEntry(nodeIP string) {
	ClientListLock.Lock()
	defer ClientListLock.Unlock()

	delete(ClientList, nodeIP)
}

// =============== //
// == KubeArmor == //
// =============== //

func connectToKubeArmor(nodeID, port string) error {
	nodeIP, err := extractIP(nodeID)
	if err != nil {
		return err
	}
	// create connection info

	server := net.JoinHostPort(nodeIP, port)
	kg.Printf("Connecting to server %s", server)

	for Running {
		ClientListLock.RLock()
		_, found := ClientList[nodeID]
		ClientListLock.RUnlock()
		if !found {
			// KubeArmor with this IP is deleted or the IP has changed
			// parent function will spawn a new goroutine accordingly
			break
		}

		// do healthcheck first before creating the log client
		healthAddr := net.JoinHostPort(nodeIP, cfg.GlobalConfig.LivenessPort)
		if ok := DoHealthCheck(nodeIP); !ok {
			kg.Warnf("Failed to check the liveness of KubeArmor's gRPC service (%s)", healthAddr)
			time.Sleep(5 * time.Second) // wait for 5 second before retrying
			continue
		}
		kg.Printf("Checked the liveness of KubeArmor's gRPC service (%s)", healthAddr)

		// create a client for log feeds
		client := NewClient(server)
		if client == nil {
			time.Sleep(5 * time.Second) // wait for 5 second before retrying
			continue
		}

		var wg sync.WaitGroup
		stop := make(chan struct{})
		errCh := make(chan error, 1)

		// Start watching messages
		wg.Add(1)
		go client.WatchMessages(&wg, stop, errCh)
		kg.Print("Started to watch messages from " + server)

		// Start watching alerts
		wg.Add(1)
		go client.WatchAlerts(&wg, stop, errCh)
		kg.Print("Started to watch alerts from " + server)

		// Start watching logs
		wg.Add(1)
		go client.WatchLogs(&wg, stop, errCh)
		kg.Print("Started to watch logs from " + server)

		//start IP informers
		kg.Print("Started to watch k8s IP's for resources")

		// Wait for an error or all goroutines to finish
		select {
		case err := <-errCh:
			close(stop) // Stop other goroutines
			kg.Warn(err.Error())
		case <-func() chan struct{} {
			done := make(chan struct{})
			go func() {
				wg.Wait()
				close(done)
			}()
			return done
		}():
			// All goroutines finished without error
		}

		if err := client.DestroyClient(); err != nil {
			kg.Warnf("Failed to destroy the client (%s) %s", server, err.Error())
		}

		kg.Printf("Destroyed the client (%s)", server)
	}
	return nil
}

// GetFeedsFromNodes Function
func (rs *RelayServer) GetFeedsFromNodes() {

	rs.WgServer.Add(1)
	defer rs.WgServer.Done()

	go rs.AddMsgFromBuffChan()
	go rs.AddAlertFromBuffChan()
	go rs.AddLogFromBuffChan()

	if K8s.InitK8sClient() {
		kg.Print("Initialized the Kubernetes client")

		ipsChan := make(chan string)
		if Running {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			rs.WgServer.Add(1)
			go K8s.WatchKubeArmorPods(ctx, &rs.WgServer, ipsChan)
			rs.WgServer.Add(1)
			go startIPInformers(ctx, &rs.WgServer)
		} else {
			close(ipsChan)
		}

		for Running {
			select {
			case ip := <-ipsChan:
				ClientListLock.Lock()
				if _, ok := ClientList[ip]; !ok {
					ClientList[ip] = 1
					go connectToKubeArmor(ip, rs.Port)
				}
				ClientListLock.Unlock()
			case <-time.After(time.Second):
				// no op
			}
		}
	} else {
		kg.Errf("Failed to initialize kubernetes config")
	}
}

func startIPInformers(ctx context.Context, wg *sync.WaitGroup) {
	kg.Printf("Started IP informers")
	defer wg.Done()

	// Check if context is already canceled
	if ctx.Err() != nil {
		kg.Errf("Context canceled before starting informers")
		return
	}

	factory := informers.NewSharedInformerFactory(K8s.K8sClient, 30*time.Second)
	podInformer := factory.Core().V1().Pods().Informer()
	svcInformer := factory.Core().V1().Services().Informer()

	updateIP := func(kind, namespace, name, ip string) {

		if ip == "" {
			return
		}
		resource := ""
		switch strings.ToUpper(kind) {

		case "POD":
			resource = fmt.Sprintf("pod/%s/%s", namespace, name)
		case "SERVICE":
			resource = fmt.Sprintf("svc/%s/%s", namespace, name)
		}

		Ipcache.Store(ip, resource)
	}

	// 4. Attach event handlers
	_, err := podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			pod, ok := obj.(*corev1.Pod)
			if !ok {
				return
			}
			updateIP("POD", pod.Namespace, pod.Name, pod.Status.PodIP)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			pod, ok := newObj.(*corev1.Pod)
			if !ok {
				return
			}

			updateIP("POD", pod.Namespace, pod.Name, pod.Status.PodIP)
		},
		DeleteFunc: func(obj interface{}) {
			pod, ok := obj.(*corev1.Pod)
			if !ok {
				return
			}
			Ipcache.Delete(pod.Status.PodIP)

		},
	})

	if err != nil {
		kg.Errf("Failed to add pod event handler: %v", err)
	}

	// Service handlers
	_, err = svcInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			svc, ok := obj.(*corev1.Service)
			if !ok {
				return
			}

			updateIP("SERVICE", svc.Namespace, svc.Name, svc.Spec.ClusterIP)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			svc, ok := newObj.(*corev1.Service)
			if !ok {
				return
			}

			updateIP("SERVICE", svc.Namespace, svc.Name, svc.Spec.ClusterIP)
		},
		DeleteFunc: func(obj interface{}) {
			svc, ok := obj.(*corev1.Service)
			if !ok {
				return
			}
			Ipcache.Delete(svc.Spec.ClusterIP)
		},
	})

	if err != nil {
		kg.Errf("Failed to add service event handler: %v", err)
	}

	factory.Start(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), podInformer.HasSynced, svcInformer.HasSynced) {
		kg.Errf("Timed out waiting for cache sync")
		return
	}

	<-ctx.Done()
	kg.Printf("Shutting down informers…")
}

func extractIPfromLog(resource string) string {
	for _, field := range strings.Fields(resource) {
		if strings.Contains(field, "remoteip=") {
			parts := strings.SplitN(field, "=", 2)
			if len(parts) == 2 && net.ParseIP(parts[1]) != nil {
				kg.Debugf("remote ip: %s", parts[1])
				return parts[1]
			}
		}
	}
	return ""
}

func addRemoteHostInfo(log *pb.Log) {
	if (log != nil) && strings.Contains(log.Data, "tcp_") {
		ip := extractIPfromLog(log.Resource)
		rawIface, found := Ipcache.Load(ip)
		if !found {
			kg.Printf("Host not found for this IP")
			return
		}

		k8sRes, ok := rawIface.(string)
		if !ok {
			return
		}

		log.Resource = fmt.Sprintf("%s remotehost=%s", log.Resource, k8sRes)
		kg.Printf("%s", log.Resource)
	}
}
