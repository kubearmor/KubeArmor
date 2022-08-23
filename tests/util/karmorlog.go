// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package util

import (
	"errors"
	"fmt"
	"strings"
	"time"

	pb "github.com/kubearmor/KubeArmor/protobuf"
	klog "github.com/kubearmor/kubearmor-client/log"
	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/encoding/protojson"
)

var eventChan chan klog.EventInfo

const maxEvents = 128

// EventResult type
type EventResult struct {
	Alerts []pb.Alert
	Logs   []pb.Log
	Found  bool
}

func getLogWithInfo(logItem pb.Log, target pb.Log) bool {
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

// KarmorGetLogs waits for logs from kubearmor. KarmorLogStart() has to be called
// before this so that the channel is established.
func KarmorGetLogs(timeout time.Duration, target pb.Log) (EventResult, error) {
	res := EventResult{}
	res.Logs = []pb.Log{}
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
				res.Logs = append(res.Logs, logItem)
			} else if evtin.Type != "Alert" {
				log.Errorf("UNKNOWN EVT type %s", evtin.Type)
			}
			if getLogWithInfo(logItem, target) {
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

// KarmorLogStart start observing for kubearmor telemetry events
func KarmorLogStart(logFilter string, ns string, op string, pod string) error {
	if eventChan == nil {
		eventChan = make(chan klog.EventInfo, maxEvents)
	}
	go func() {
		err := klog.StartObserver(klog.Options{
			LogFilter: logFilter,
			Namespace: ns,
			Operation: op,
			PodName:   pod,
			MsgPath:   "none",
			EventChan: eventChan,
		})
		if err != nil {
			log.Errorf("failed to start observer. Error=%s", err.Error())
		}
	}()
	return nil
}

func getAlertWithInfo(alert pb.Alert, target pb.Alert) bool {

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

	return true
}

// KarmorGetAlert looks for target alert in telemetry events
func KarmorGetAlert(timeout time.Duration, target pb.Alert) (EventResult, error) {
	res := EventResult{}
	res.Alerts = []pb.Alert{}
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
				res.Alerts = append(res.Alerts, alert)
				fmt.Printf("Alert: %s\n", &alert)
			} else if evtin.Type != "Log" {
				log.Errorf("UNKNOWN EVT type %s", evtin.Type)
			}
			if getAlertWithInfo(alert, target) {
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

// KarmorLogStop stops the kubearmor-client observer
func KarmorLogStop() {
	klog.StopObserver()
}
