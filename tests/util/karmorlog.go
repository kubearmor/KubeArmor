// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

// Package util contains helper functions needed by unit tests
package util

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/kubearmor/KubeArmor/KubeArmor/cert"
	pb "github.com/kubearmor/KubeArmor/protobuf"
	klog "github.com/kubearmor/kubearmor-client/log"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protojson"
)

// EventResult type
type EventResult struct {
	Alerts []*pb.Alert
	Logs   []*pb.Log
	Found  bool
}

var eventChan chan klog.EventInfo
var hostLogCancel context.CancelFunc
var gRPC = ""

const maxEvents = 128

func getLogWithInfo(logItem *pb.Log, target *pb.Log) bool {
	if target.Source != "" {
		if !strings.Contains(logItem.Source, target.Source) {
			return false
		}
	}
	if target.Resource != "" {
		if !strings.Contains(logItem.Resource, target.Resource) {
			return false
		}
	}
	if target.Result != "" {
		if logItem.Result != target.Result {
			return false
		}
	}
	return true
}

// KarmorGetTargetLogs waits for logs from kubearmor. KarmorLogStart() has to be called
// before this so that the channel is established.
func KarmorGetTargetLogs(timeout time.Duration, target *pb.Log) (EventResult, error) {
	res := EventResult{}
	res.Logs = []*pb.Log{}
	res.Found = false
	if eventChan == nil {
		log.Error("event channel not set. Did you call KarmorQueueLog()?")
		return res, errors.New("event channel not set")
	}
	evtCnt := 0
	breakAway := false
	logItem := pb.Log{}
	for eventChan != nil {
		select {
		case evtin := <-eventChan:
			if evtin.Type == "Log" {
				protojson.Unmarshal(evtin.Data, &logItem)
				res.Logs = append(res.Logs, &logItem)
				// fmt.Printf("Log: %s\n", &logItem)
			} else if evtin.Type != "Alert" {
				log.Errorf("UNKNOWN EVT type %s", evtin.Type)
			}
			if getLogWithInfo(&logItem, target) {
				log.Printf("Found Target Log")
				fmt.Printf("Alert: %s\n", &logItem)
				res.Found = true
				return res, nil

			}
			evtCnt++
			if evtCnt >= maxEvents {
				breakAway = true
			}
		case <-time.After(timeout):
			log.Info("event timeout")
			breakAway = true
		}
		if breakAway {
			break
		}
	}
	return res, nil
}

func getAlertWithInfo(alert *pb.Alert, target *pb.Alert) bool {
	if target.PolicyName != "" {
		if alert.PolicyName != target.PolicyName {
			return false
		}
	}
	if target.Severity != "" {
		if alert.Severity != target.Severity {
			return false
		}
	}
	if target.Action != "" {
		if alert.Action != target.Action {
			return false
		}
	}
	if target.Result != "" {
		if alert.Result != target.Result {
			return false
		}
	}
	if target.Message != "" {
		if alert.Message != target.Message {
			return false
		}
	}
	if target.Resource != "" {
		if !strings.Contains(alert.Resource, target.Resource) {
			return false
		}
	}
	if target.Source != "" {
		if !strings.Contains(alert.Source, target.Source) {
			return false
		}
	}
	if target.NamespaceName != "" {
		if alert.NamespaceName != target.NamespaceName {
			return false
		}
	}
	if target.Data != "" {
		if !strings.Contains(alert.Data, target.Data) {
			return false
		}
	}
	if target.ContainerName != "" {
		if !strings.Contains(alert.ContainerName, target.ContainerName) {
			return false
		}
	}

	return true
}

// KarmorGetTargetAlert looks for target alert in telemetry events
func KarmorGetTargetAlert(timeout time.Duration, target *pb.Alert) (EventResult, error) {
	res := EventResult{}
	res.Alerts = []*pb.Alert{}
	res.Found = false
	if eventChan == nil {
		log.Error("event channel not set. Did you call KarmorQueueLog()?")
		return res, errors.New("event channel not set")
	}
	evtCnt := 0
	breakAway := false
	alert := pb.Alert{}
	for eventChan != nil {
		select {
		case evtin := <-eventChan:
			if evtin.Type == "Alert" {
				protojson.Unmarshal(evtin.Data, &alert)
				res.Alerts = append(res.Alerts, &alert)
			} else if evtin.Type != "Log" {
				log.Errorf("UNKNOWN EVT type %s", evtin.Type)
			}

			if getAlertWithInfo(&alert, target) {
				log.Printf("Found Target Alert")
				fmt.Printf("Alert: %s\n", &alert)
				res.Found = true
				return res, nil

			}
			evtCnt++
			if evtCnt >= maxEvents {
				breakAway = true
			}
		case <-time.After(timeout):
			log.Info("event timeout")
			breakAway = true
		}
		if breakAway {
			break
		}
	}
	return res, nil
}

// drainEventChan drains all events from the eventChan.
func drainEventChan() {
	if eventChan == nil {
		return
	}
	for {
		select {
		case <-eventChan:
		default:
			return
		}
	}
}

// KarmorLogStart start observing for kubearmor telemetry events
func KarmorLogStart(logFilter string, ns string, op string, pod string) error {
	// reset eventChan
	drainEventChan()

	if eventChan == nil {
		eventChan = make(chan klog.EventInfo, maxEvents)
	}
	go func() {
		var opt klog.Options
		if ns != "" && pod != "" { // for pod
			opt = klog.Options{
				LogFilter:        logFilter,
				ReadCAFromSecret: true,
				TlsCertPath:      "/var/lib/kubearmor/tls",
				TlsCertProvider:  klog.SelfCertProvider,
				Namespace:        ns,
				Operation:        op,
				PodName:          pod,
				MsgPath:          "none",
				EventChan:        eventChan,
				GRPC:             gRPC,
			}
		} else { // for host
			opt = klog.Options{
				LogFilter:        logFilter,
				ReadCAFromSecret: true,
				TlsCertPath:      "/var/lib/kubearmor/tls",
				TlsCertProvider:  klog.SelfCertProvider,
				Operation:        op,
				MsgPath:          "none",
				EventChan:        eventChan,
				GRPC:             gRPC,
			}
		}
		err := klog.StartObserver(k8sClient, opt)
		if err != nil {
			log.Errorf("failed to start observer. Error=%s", err.Error())
		}
	}()
	time.Sleep(2 * time.Second)
	return nil
}

func logGRPCAddress() string {
	if val, ok := os.LookupEnv("KUBEARMOR_LOG_SERVICE"); ok {
		return val
	}
	if val, ok := os.LookupEnv("KUBEARMOR_SERVICE"); ok {
		return val
	}
	return "localhost:32767"
}

func newLogGRPCClient() (*grpc.ClientConn, error) {
	tlsConfig := cert.TlsConfig{
		CertProvider: cert.ExternalCertProvider,
		CACertPath:   cert.GetCACertPath(kubearmorTLSPath()),
		CertPath:     cert.GetClientCertPath(kubearmorTLSPath()),
	}
	creds, err := cert.NewTlsCredentialManager(&tlsConfig).CreateTlsClientCredentials()
	if err != nil {
		return nil, err
	}
	return grpc.NewClient(logGRPCAddress(), grpc.WithTransportCredentials(creds))
}

func KarmorHostLogStart(logFilter string, op string) error {
	if hostLogCancel != nil {
		hostLogCancel()
		hostLogCancel = nil
	}
	drainEventChan()

	if eventChan == nil {
		eventChan = make(chan klog.EventInfo, maxEvents)
	}

	conn, err := newLogGRPCClient()
	if err != nil {
		return err
	}
	client := pb.NewLogServiceClient(conn)
	ctx, cancel := context.WithCancel(context.Background())
	hostLogCancel = cancel

	go func() {
		defer conn.Close()
		req := pb.RequestMessage{Filter: logFilter}

		if logFilter == "all" || logFilter == "policy" {
			alertStream, err := client.WatchAlerts(ctx, &req)
			if err != nil {
				log.Errorf("failed to watch alerts. Error=%s", err.Error())
				return
			}
			for {
				alert, err := alertStream.Recv()
				if err != nil {
					return
				}
				data, _ := json.Marshal(alert)
				eventChan <- klog.EventInfo{Type: "Alert", Data: data}
			}
		}

		if logFilter == "all" || logFilter == "system" {
			logStream, err := client.WatchLogs(ctx, &req)
			if err != nil {
				log.Errorf("failed to watch logs. Error=%s", err.Error())
				return
			}
			for {
				logEvent, err := logStream.Recv()
				if err != nil {
					return
				}
				if op != "" && logEvent.Operation != op {
					continue
				}
				data, _ := json.Marshal(logEvent)
				eventChan <- klog.EventInfo{Type: "Log", Data: data}
			}
		}
	}()

	time.Sleep(3 * time.Second)
	return nil
}

// KarmorGetLogs waits for logs from kubearmor. KarmorQueueLog() has to be called
// before this so that the channel is established.
func KarmorGetLogs(timeout time.Duration, maxEvents int) ([]*pb.Log, []*pb.Alert, error) {
	if eventChan == nil {
		log.Error("event channel not set. Did you call KarmorQueueLog()?")
		return nil, nil, errors.New("event channel not set")
	}
	logs := []*pb.Log{}
	alerts := []*pb.Alert{}
	evtCnt := 0
	breakAway := false
	for eventChan != nil {
		select {
		case evtin := <-eventChan:
			switch evtin.Type {
			case "Alert":
				alert := pb.Alert{}
				protojson.Unmarshal(evtin.Data, &alert)
				alerts = append(alerts, &alert)
			case "Log":
				log := pb.Log{}
				protojson.Unmarshal(evtin.Data, &log)
				logs = append(logs, &log)
			default:
				log.Errorf("UNKNOWN EVT type %s", evtin.Type)
			}
			evtCnt++
			if evtCnt >= maxEvents {
				breakAway = true
			}
		case <-time.After(timeout):
			log.Info("event timeout")
			breakAway = true
		}
		if breakAway {
			break
		}
	}
	return logs, alerts, nil
}

// KarmorLogStop stops the kubearmor-client observer
func KarmorLogStop() {
	if hostLogCancel != nil {
		hostLogCancel()
		hostLogCancel = nil
	}

	klog.UnblockSignal = errors.New("stop karmor logs")

}

// GetOperations Function
func GetOperations(logs []*pb.Log) []string {
	optsMap := make(map[string]int)
	opts := []string{}
	for _, log := range logs {
		optsMap[log.Operation] = 1
	}
	for operation := range optsMap {
		opts = append(opts, strings.ToLower(operation))
	}

	return opts
}

// IsOperationsExpected validates what KubeArmor Operation is expected based on visibility configuration
func IsOperationsExpected(operations []string, expected []string) bool {
	if len(operations) != len(expected) {
		return true
	}
	for _, operation := range operations {
		found := false
		for _, expectedOp := range expected {
			if operation == expectedOp {
				found = true
				break
			}
		}
		if !found {
			fmt.Printf("Operation not found %v %v", operation, expected)
			return false
		}
	}
	return true
}
