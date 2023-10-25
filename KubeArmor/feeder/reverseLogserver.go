// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of KubeArmor

package feeder

import (
	"sync"
	"time"

	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	kg "github.com/kubearmor/KubeArmor/KubeArmor/log"
	pb "github.com/kubearmor/KubeArmor/protobuf"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"
)

// ReverseLogService Structure
type ReverseLogService struct {
	Conn   *grpc.ClientConn
	Client pb.ReverseLogServiceClient

	ReverseLogClient     pb.ReverseLogService_PushLogsClient
	ReverseAlertClient   pb.ReverseLogService_PushAlertsClient
	ReverseMessageClient pb.ReverseLogService_PushMessagesClient

	QueueSize    int
	EventStructs *EventStructs
	Running      *bool
	Wg           sync.WaitGroup
}

func (ls *ReverseLogService) WatchMessages() {
	defer ls.Wg.Done()
	if ls.Running == nil {
		return
	}

	// add a new message struct
	uid, conn := ls.EventStructs.AddMsgStruct("none", ls.QueueSize)
	kg.Printf("Added a new connection (%s) for ReverseWatchMessages", uid)

	defer func() {
		close(conn)
		ls.EventStructs.RemoveMsgStruct(uid)
		kg.Printf("Deleted the connection (%s) for ReverseWatchMessages", uid)
		kg.Printf("Stopped pushing messages to ReverseWatchMessages Client (%s)", uid)
	}()

	closeChan := make(chan *pb.ReplyMessage, 1)

	// handle if server closes connection
	go func() {
		defer close(closeChan)
		resp, err := ls.ReverseMessageClient.Recv()
		if err := kl.HandleGRPCErrors(err); err != nil {
			kg.Debugf("Error while receiving ReplyMessage msg from relay %s", err.Error())
			closeChan <- &pb.ReplyMessage{}
			return
		}
		closeChan <- resp
	}()

	for *ls.Running {
		select {
		case <-ls.ReverseMessageClient.Context().Done():
			return
		case <-closeChan:
			kg.Printf("Relay closed connection for Messages")
			return
		case resp := <-conn:
			if err := kl.HandleGRPCErrors(ls.ReverseMessageClient.Send(resp)); err != nil {
				kg.Warnf("feeder failed to send a message=[%+v] err=[%s]", resp, err.Error())
				return
			}
		}
	}

}

func (ls *ReverseLogService) WatchAlerts() {
	defer ls.Wg.Done()
	if ls.Running == nil {
		return
	}

	uid, conn := ls.EventStructs.AddAlertStruct("none", ls.QueueSize)
	kg.Printf("Added a new connection (%s) for ReverseWatchAlerts", uid)

	defer func() {
		close(conn)
		ls.EventStructs.RemoveAlertStruct(uid)
		kg.Printf("Deleted connection (%s) for ReverseWatchAlerts", uid)
		kg.Printf("Stopped pushing alerts to ReverseWatchAlerts client (%s)", uid)
	}()

	closeChan := make(chan *pb.ReplyMessage, 1)

	go func() {
		defer close(closeChan)
		resp, err := ls.ReverseAlertClient.Recv()
		if err := kl.HandleGRPCErrors(err); err != nil {
			kg.Debugf("Error while receiving ReplyMessage alert from relay %s", err.Error())
			closeChan <- &pb.ReplyMessage{}
			return
		}
		closeChan <- resp
	}()

	for *ls.Running {
		select {
		case <-ls.ReverseAlertClient.Context().Done():
			return
		case <-closeChan:
			kg.Printf("Relay closed connection for Alerts")
			return
		case resp := <-conn:
			if err := kl.HandleGRPCErrors(ls.ReverseAlertClient.Send(resp)); err != nil {
				kg.Warnf("feeder failed to push an alert=[%+v] err=[%s]", resp, err.Error())
				return
			}
		}
	}

}

func (ls *ReverseLogService) WatchLogs() {
	defer ls.Wg.Done()
	if ls.Running == nil {
		return
	}

	uid, conn := ls.EventStructs.AddLogStruct("none", ls.QueueSize)
	kg.Printf("Added a new connection (%s) for ReverseWatchLogs", uid)

	defer func() {
		close(conn)
		ls.EventStructs.RemoveLogStruct(uid)
		kg.Printf("Deleted connection (%s) for ReverseWatchLogs", uid)
		kg.Printf("Stopped pushing logs to ReverseWatchLogs client (%s)", uid)
	}()

	closeChan := make(chan *pb.ReplyMessage, 1)

	go func() {
		defer close(closeChan)
		resp, err := ls.ReverseLogClient.Recv()
		if err := kl.HandleGRPCErrors(err); err != nil {
			kg.Debugf("Error while receiving ReplyMessage log from relay %s", err.Error())
			closeChan <- &pb.ReplyMessage{}
			return
		}
		closeChan <- resp
	}()

	for *ls.Running {
		select {
		case <-ls.ReverseLogClient.Context().Done():
			return
		case <-closeChan:
			kg.Printf("Relay closed connection for Logs")
			return
		case resp := <-conn:
			if err := kl.HandleGRPCErrors(ls.ReverseLogClient.Send(resp)); err != nil {
				kg.Warnf("failed to push a log=[%+v] err=[%s]", resp, err.Error())
				return
			}
		}
	}

}

// ConnectWithRelay attemtps to establish a connection with kubearmor-relay
// until the relay is healthy
func (fd *BaseFeeder) ConnectWithRelay() *ReverseLogService {
	var (
		err    error
		conn   *grpc.ClientConn
		client pb.ReverseLogServiceClient
	)

	kacp := keepalive.ClientParameters{
		Time:                1 * time.Second,
		Timeout:             5 * time.Second,
		PermitWithoutStream: true,
	}

	for fd.Running {
		//conn, err = grpc.Dial(fd.RelayServerURL, grpc.WithInsecure(), grpc.WithKeepaliveParams(kacp))
		conn, err = grpc.DialContext(fd.Context, fd.RelayServerURL, grpc.WithInsecure(), grpc.WithKeepaliveParams(kacp))
		if err != nil {
			time.Sleep(time.Second * 5)
			_ = conn.Close()
			continue
		}

		client = pb.NewReverseLogServiceClient(conn)

		healthClient := grpc_health_v1.NewHealthClient(conn)
		healthCheckRequest := &grpc_health_v1.HealthCheckRequest{
			Service: pb.ReverseLogService_ServiceDesc.ServiceName,
		}

		resp, err := healthClient.Check(fd.Context, healthCheckRequest)
		grpcErr := kl.HandleGRPCErrors(err)
		if grpcErr != nil {
			kg.Debugf("ReverseLogServer unhealthy. Error: %s", grpcErr.Error())
			_ = conn.Close()
			time.Sleep(time.Second * 5)
			continue
		}

		switch resp.Status {
		case grpc_health_v1.HealthCheckResponse_SERVING:
			break
		case grpc_health_v1.HealthCheckResponse_NOT_SERVING:
			_ = conn.Close()
			return nil
		default:
			kg.Debugf("ReverseLogServer unhealthy. Status: %s", resp.Status.String())
			_ = conn.Close()
			time.Sleep(time.Second * 5)
			continue
		}

		break
	}

	lc := &ReverseLogService{
		Conn:         conn,
		Client:       client,
		Wg:           sync.WaitGroup{},
		EventStructs: fd.EventStructs,
		QueueSize:    1000,
		Running:      &fd.Running,
	}

	//lc.ReverseLogClient, err = lc.Client.PushLogs(context.Background())
	lc.ReverseLogClient, err = lc.Client.PushLogs(fd.Context)
	if err != nil {
		kg.Warnf("Failed to create ReversePushLogs (%s) err=%s", fd.RelayServerURL, err.Error())
		return nil
	}

	//lc.ReverseAlertClient, err = lc.Client.PushAlerts(context.Background())
	lc.ReverseAlertClient, err = lc.Client.PushAlerts(fd.Context)
	if err != nil {
		kg.Warnf("Failed to create ReversePushAlerts (%s) err=%s", fd.RelayServerURL, err.Error())
		return nil
	}

	//lc.ReverseMessageClient, err = lc.Client.PushMessages(context.Background())
	lc.ReverseMessageClient, err = lc.Client.PushMessages(fd.Context)
	if err != nil {
		kg.Warnf("Failed to create ReversePushMessages (%s) err=%s", fd.RelayServerURL, err.Error())
		return nil
	}

	return lc
}
