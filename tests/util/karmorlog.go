// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

// Package util declaration
package util

import (
	"errors"
	"time"

	pb "github.com/kubearmor/KubeArmor/protobuf"
	klog "github.com/kubearmor/kubearmor-client/log"
	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/encoding/protojson"
)

var eventChan chan klog.EventInfo

const maxEvents = 128

// KarmorGetLogs function. WaitForLogs waits for logs from kubearmor. KarmorQueueLog() has to be called
// before this so that the channel is established.
func KarmorGetLogs(timeout time.Duration, maxEvents int) ([]pb.Log, []pb.Alert, error) {
	if eventChan == nil {
		log.Error("event channel not set. Did you call KarmorQueueLog()?")
		return nil, nil, errors.New("event channel not set")
	}
	logs := []pb.Log{}
	alerts := []pb.Alert{}
	evtCnt := 0
	breakAway := false
	for eventChan != nil {
		select {
		case evtin := <-eventChan:
			if evtin.Type == "Alert" {
				alert := pb.Alert{}
				protojson.Unmarshal(evtin.Data, &alert)
				alerts = append(alerts, alert)
			} else if evtin.Type == "Log" {
				log := pb.Log{}
				protojson.Unmarshal(evtin.Data, &log)
				logs = append(logs, log)
			} else {
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

// KarmorLogStop stops the kubearmor-client observer
func KarmorLogStop() {
	klog.StopObserver()
}
