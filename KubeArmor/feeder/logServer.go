// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package feeder

import (
	"context"
	"fmt"

	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	kg "github.com/kubearmor/KubeArmor/KubeArmor/log"
	pb "github.com/kubearmor/KubeArmor/protobuf"
)

// LogService struct holds the state of feeder's log server
type LogService struct {
	QueueSize    int
	EventStructs *EventStructs
	Running      *bool
}

// HealthCheck Function
// Deprecated: use the server created with google.golang.org/grpc/health/grpc_health_v1
func (ls *LogService) HealthCheck(ctx context.Context, nonce *pb.NonceMessage) (*pb.ReplyMessage, error) {
	replyMessage := pb.ReplyMessage{Retval: nonce.Nonce}
	return &replyMessage, nil
}

// WatchMessages Function
func (ls *LogService) WatchMessages(req *pb.RequestMessage, svr pb.LogService_WatchMessagesServer) error {
	if ls.Running == nil {
		return fmt.Errorf("Feeder is not running")
	}

	uid, conn := ls.EventStructs.AddMsgStruct(req.Filter, ls.QueueSize)
	kg.Printf("Added a new client (%s) for WatchMessages", uid)

	defer func() {
		close(conn)
		ls.EventStructs.RemoveMsgStruct(uid)
		kg.Printf("Deleted the client (%s) for WatchMessages", uid)
	}()

	for *ls.Running {
		select {
		case <-svr.Context().Done():
			return nil
		case resp := <-conn:
			if err := kl.HandleGRPCErrors(svr.Send(resp)); err != nil {
				kg.Warnf("Failed to send a message=[%+v] err=[%s]", resp, err.Error())
				return err
			}
		}
	}

	return nil
}

// WatchAlerts Function
func (ls *LogService) WatchAlerts(req *pb.RequestMessage, svr pb.LogService_WatchAlertsServer) error {
	if ls.Running == nil {
		return fmt.Errorf("Feeder is not running")
	}

	if req.Filter != "all" && req.Filter != "policy" {
		return nil
	}

	uid, conn := ls.EventStructs.AddAlertStruct(req.Filter, ls.QueueSize)
	kg.Printf("Added a new client (%s, %s) for WatchAlerts", uid, req.Filter)

	defer func() {
		close(conn)
		ls.EventStructs.RemoveAlertStruct(uid)
		kg.Printf("Deleted the client (%s) for WatchAlerts", uid)
	}()

	for *ls.Running {
		select {
		case <-svr.Context().Done():
			return nil
		case resp := <-conn:
			if err := kl.HandleGRPCErrors(svr.Send(resp)); err != nil {
				kg.Warnf("Failed to send an alert=[%+v] err=[%s]", resp, err.Error())
				return err
			}
		}
	}

	return nil
}

// WatchLogs Function
func (ls *LogService) WatchLogs(req *pb.RequestMessage, svr pb.LogService_WatchLogsServer) error {
	if ls.Running == nil {
		return fmt.Errorf("Feeder is not running")
	}

	if req.Filter != "all" && req.Filter != "system" {
		return nil
	}

	uid, conn := ls.EventStructs.AddLogStruct(req.Filter, ls.QueueSize)
	kg.Printf("Added a new client (%s, %s) for WatchLogs", uid, req.Filter)

	defer func() {
		close(conn)
		ls.EventStructs.RemoveLogStruct(uid)
		kg.Printf("Deleted the client (%s) for WatchLogs", uid)
	}()

	for *ls.Running {
		select {
		case <-svr.Context().Done():
			return nil
		case resp := <-conn:
			if err := kl.HandleGRPCErrors(svr.Send(resp)); err != nil {
				kg.Warnf("Failed to send a log=[%+v] err=[%s]", resp, err.Error())
				return err
			}
		}
	}

	return nil
}
