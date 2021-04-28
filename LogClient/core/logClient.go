package core

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"strings"
	"sync"

	ll "github.com/accuknox/KubeArmor/LogClient/common"

	pb "github.com/accuknox/KubeArmor/protobuf"
	"google.golang.org/grpc"
)

// =============== //
// == Log Feeds == //
// =============== //

// LogClient Structure
type LogClient struct {
	// server
	server string

	// connection
	conn *grpc.ClientConn

	// client
	client pb.LogServiceClient

	// messages
	msgStream pb.LogService_WatchMessagesClient

	// logs
	logStream pb.LogService_WatchLogsClient

	// wait group
	WgClient sync.WaitGroup
}

// NewClient Function
func NewClient(server, msgPath, logPath, logFilter string) *LogClient {
	lc := &LogClient{}

	lc.server = server

	conn, err := grpc.Dial(lc.server, grpc.WithInsecure())
	if err != nil {
		fmt.Errorf("Failed to connect to a gRPC server (%s)", err.Error())
		return nil
	}
	lc.conn = conn

	lc.client = pb.NewLogServiceClient(lc.conn)

	if msgPath != "none" {
		msgIn := pb.RequestMessage{}
		msgIn.Filter = ""

		msgStream, err := lc.client.WatchMessages(context.Background(), &msgIn)
		if err != nil {
			fmt.Errorf("Failed to call WatchMessages() (%s)", err.Error())
			return nil
		}
		lc.msgStream = msgStream
	}

	if logPath != "none" {
		logIn := pb.RequestMessage{}

		if logFilter == "all" {
			logIn.Filter = ""
		} else {
			logIn.Filter = logFilter
		}

		logStream, err := lc.client.WatchLogs(context.Background(), &logIn)
		if err != nil {
			fmt.Errorf("Failed to call WatchLogs() (%s)", err.Error())
			return nil
		}
		lc.logStream = logStream
	}

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
func (lc *LogClient) WatchMessages(msgPath string, jsonFormat bool) error {
	lc.WgClient.Add(1)
	defer lc.WgClient.Done()

	for {
		res, err := lc.msgStream.Recv()
		if err != nil {
			fmt.Errorf("Failed to receive a message (%s)", err.Error())
			break
		}

		str := ""

		if jsonFormat {
			arr, _ := json.Marshal(res)
			str = fmt.Sprintf("%s\n", string(arr))
		} else {
			updatedTime := strings.Replace(res.UpdatedTime, "T", " ", -1)
			updatedTime = strings.Replace(updatedTime, "Z", "", -1)

			str = fmt.Sprintf("%s  %s  [%s]  %s\n", updatedTime, res.Source, res.Level, res.Message)
		}

		if msgPath == "stdout" {
			fmt.Printf("%s", str)
		} else {
			ll.StrToFile(str, msgPath)
		}
	}

	return nil
}

// WatchLogs Function
func (lc *LogClient) WatchLogs(logPath string, jsonFormat bool) error {
	lc.WgClient.Add(1)
	defer lc.WgClient.Done()

	for {
		res, err := lc.logStream.Recv()
		if err != nil {
			fmt.Errorf("Failed to receive a log (%s)", err.Error())
			break
		}

		str := ""

		if jsonFormat {
			arr, _ := json.Marshal(res)
			str = fmt.Sprintf("%s\n", string(arr))
		} else {
			updatedTime := strings.Replace(res.UpdatedTime, "T", " ", -1)
			updatedTime = strings.Replace(updatedTime, "Z", "", -1)

			str = fmt.Sprintf("== Log / %s ==\n", updatedTime)

			str = str + fmt.Sprintf("Host Name: %s\n", res.HostName)

			if res.NamespaceName != "" {
				str = str + fmt.Sprintf("Namespace Name: %s\n", res.NamespaceName)
				str = str + fmt.Sprintf("Pod Name: %s\n", res.PodName)
				str = str + fmt.Sprintf("Container ID: %s\n", res.ContainerID)
				str = str + fmt.Sprintf("Container Name: %s\n", res.ContainerName)
			}

			if len(res.PolicyName) > 0 {
				str = str + fmt.Sprintf("Policy Name: %s\n", res.PolicyName)
			}

			if len(res.Severity) > 0 {
				str = str + fmt.Sprintf("Severity: %s\n", res.Severity)
			}

			if len(res.Tags) > 0 {
				str = str + fmt.Sprintf("Tags: %s\n", res.Tags)
			}

			if len(res.Message) > 0 {
				str = str + fmt.Sprintf("Message: %s\n", res.Message)
			}

			str = str + fmt.Sprintf("Type: %s\n", res.Type)
			str = str + fmt.Sprintf("Source: %s\n", res.Source)
			str = str + fmt.Sprintf("Operation: %s\n", res.Operation)
			str = str + fmt.Sprintf("Resource: %s\n", res.Resource)

			if len(res.Data) > 0 {
				str = str + fmt.Sprintf("Data: %s\n", res.Data)
			}

			if len(res.Action) > 0 {
				str = str + fmt.Sprintf("Action: %s\n", res.Action)
			}

			str = str + fmt.Sprintf("Result: %s\n", res.Result)
		}

		if logPath == "stdout" {
			fmt.Printf("%s", str)
		} else {
			ll.StrToFile(str, logPath)
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
