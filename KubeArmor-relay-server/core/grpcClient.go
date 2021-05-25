package core

import (
	"context"
	"fmt"
	"math/rand"
	"sync"

	pb "github.com/accuknox/KubeArmor/protobuf"
	"google.golang.org/grpc"
)

// =============== //
// == Log Feeds == //
// =============== //

// LogClient Structure
type LogClient struct {
	// flag
	Running bool

	// server
	server string

	// connection
	conn *grpc.ClientConn

	// client
	client pb.LogServiceClient

	// messages
	msgStream pb.LogService_WatchMessagesClient

	// alerts
	alertStream pb.LogService_WatchAlertsClient

	// logs
	logStream pb.LogService_WatchLogsClient

	// wait group
	WgClient sync.WaitGroup
}

// NewClient Function
func NewClient(server string) *LogClient {
	lc := &LogClient{}

	lc.Running = true

	lc.server = server

	conn, err := grpc.Dial(lc.server, grpc.WithInsecure())
	if err != nil {
		fmt.Errorf("Failed to connect to a gRPC server (%s)", err.Error())
		return nil
	}
	lc.conn = conn

	lc.client = pb.NewLogServiceClient(lc.conn)

	msgIn := pb.RequestMessage{}
	msgIn.Filter = ""

	msgStream, err := lc.client.WatchMessages(context.Background(), &msgIn)
	if err != nil {
		fmt.Errorf("Failed to call WatchMessages() (%s)", err.Error())
		return nil
	}
	lc.msgStream = msgStream

	alertIn := pb.RequestMessage{}
	alertIn.Filter = ""

	alertStream, err := lc.client.WatchAlerts(context.Background(), &alertIn)
	if err != nil {
		fmt.Errorf("Failed to call WatchAlerts() (%s)", err.Error())
		return nil
	}
	lc.alertStream = alertStream

	logIn := pb.RequestMessage{}
	logIn.Filter = ""

	logStream, err := lc.client.WatchLogs(context.Background(), &logIn)
	if err != nil {
		fmt.Errorf("Failed to call WatchLogs() (%s)", err.Error())
		return nil
	}
	lc.logStream = logStream

	lc.WgClient = sync.WaitGroup{}

	return lc
}

// DoHealthCheck Function
func (lc *LogClient) DoHealthCheck() bool {
	// generate a nonce
	randNum := rand.Int31()

	// send a nonce
	nonce := pb.NonceMessage{Nonce: randNum}
	res, err := lc.client.HealthCheck(context.Background(), &nonce)
	if err != nil {
		fmt.Errorf("Failed to call HealthCheck() (%s)", err.Error())
		return false
	}

	// check nonce
	if randNum != res.Retval {
		return false
	}

	return true
}

// WatchMessages Function
func (lc *LogClient) WatchMessages() error {
	lc.WgClient.Add(1)
	defer lc.WgClient.Done()

	for lc.Running {
		res, err := lc.msgStream.Recv()
		if err != nil {
			fmt.Errorf("Failed to receive a message (%s)", err.Error())
			break
		}

		MsgQueue <- *res
	}

	return nil
}

// WatchAlerts Function
func (lc *LogClient) WatchAlerts() error {
	lc.WgClient.Add(1)
	defer lc.WgClient.Done()

	for lc.Running {
		res, err := lc.alertStream.Recv()
		if err != nil {
			fmt.Errorf("Failed to receive a log (%s)", err.Error())
			break
		}

		AlertQueue <- *res
	}

	return nil
}

// WatchLogs Function
func (lc *LogClient) WatchLogs() error {
	lc.WgClient.Add(1)
	defer lc.WgClient.Done()

	for lc.Running {
		res, err := lc.logStream.Recv()
		if err != nil {
			fmt.Errorf("Failed to receive a log (%s)", err.Error())
			break
		}

		select {
		case LogQueue <- *res:
			// non-blocking: possible to loss some of logs
		}

	}

	return nil
}

// DestroyClient Function
func (lc *LogClient) DestroyClient() error {
	if err := lc.conn.Close(); err != nil {
		return err
	}

	lc.WgClient.Wait()

	return nil
}
