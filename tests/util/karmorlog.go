package util

import (
	"errors"
	"reflect"
	"time"

	pb "github.com/kubearmor/KubeArmor/protobuf"
	klog "github.com/kubearmor/kubearmor-client/log"
	log "github.com/sirupsen/logrus"
)

var eventChan chan interface{}

const maxEvents = 128

// WaitForLogs waits for logs from kubearmor. KarmorQueueLog() has to be called
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
			switch evt := evtin.(type) {
			case pb.Alert:
				alerts = append(alerts, evt)
			case pb.Log:
				logs = append(logs, evt)
			default:
				log.Errorf("UNKNOWN EVT type %v", reflect.TypeOf(evt))
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

// KarmorQueueLog start observing for kubearmor telemetry events
func KarmorLogStart(logFilter string, ns string, op string, pod string) error {
	if eventChan == nil {
		eventChan = make(chan interface{}, maxEvents)
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

func KarmorLogStop() {
	klog.StopObserver()
}
