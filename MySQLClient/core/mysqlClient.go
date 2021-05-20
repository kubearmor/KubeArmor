package core

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"sync"

	ll "github.com/accuknox/KubeArmor/MySQLClient/common"

	pb "github.com/accuknox/KubeArmor/protobuf"
	"google.golang.org/grpc"
)

// =============== //
// == Log Feeds == //
// =============== //

// MySQLClient Structure
type MySQLClient struct {
	// server
	server string

	// db info
	dbHost   string
	dbName   string
	dbUser   string
	dbPasswd string

	// tables
	dbMsgTable   string
	dbAlertTable string
	dbLogTable   string

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
func NewClient(server, dbHost, dbName, dbUser, dbPasswd, dbMsgTable, dbAlertTable, dbLogTable string) *MySQLClient {
	mc := &MySQLClient{}

	mc.server = server

	mc.dbHost = dbHost
	mc.dbName = dbName
	mc.dbUser = dbUser
	mc.dbPasswd = dbPasswd

	mc.dbMsgTable = dbMsgTable
	mc.dbAlertTable = dbAlertTable
	mc.dbLogTable = dbLogTable

	conn, err := grpc.Dial(mc.server, grpc.WithInsecure())
	if err != nil {
		fmt.Errorf("Failed to connect to a gRPC server (%s)", err.Error())
		return nil
	}
	mc.conn = conn

	mc.client = pb.NewLogServiceClient(mc.conn)

	if dbMsgTable != "" {
		msgIn := pb.RequestMessage{}
		msgIn.Filter = ""

		msgStream, err := mc.client.WatchMessages(context.Background(), &msgIn)
		if err != nil {
			fmt.Errorf("Failed to call WatchMessages() (%s)", err.Error())
			return nil
		}
		mc.msgStream = msgStream
	}

	if dbAlertTable != "" {
		alertIn := pb.RequestMessage{}
		alertIn.Filter = ""

		alertStream, err := mc.client.WatchAlerts(context.Background(), &alertIn)
		if err != nil {
			fmt.Errorf("Failed to call WatchAlerts() (%s)", err.Error())
			return nil
		}
		mc.alertStream = alertStream
	}

	if dbLogTable != "" {
		logIn := pb.RequestMessage{}
		logIn.Filter = ""

		logStream, err := mc.client.WatchLogs(context.Background(), &logIn)
		if err != nil {
			fmt.Errorf("Failed to call WatchLogs() (%s)", err.Error())
			return nil
		}
		mc.logStream = logStream
	}

	mc.WgClient = sync.WaitGroup{}

	return mc
}

// DoHealthCheck Function
func (mc *MySQLClient) DoHealthCheck() bool {
	// generate a nonce
	randNum := rand.Int31()

	// send a nonce
	nonce := pb.NonceMessage{Nonce: randNum}
	res, err := mc.client.HealthCheck(context.Background(), &nonce)
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
func (mc *MySQLClient) WatchMessages(msgPath string) error {
	db := mc.ConnectMySQL()
	defer db.Close()

	mc.WgClient.Add(1)
	defer mc.WgClient.Done()

	for {
		res, err := mc.msgStream.Recv()
		if err != nil {
			fmt.Errorf("Failed to receive a message (%s)", err.Error())
			break
		}

		arr, _ := json.Marshal(res)
		str := fmt.Sprintf("%s\n", string(arr))

		sql := "INSERT INTO " + mc.dbMsgTable +
			" (timestamp, updatedTime, clusterName, hostName, hostIP, level, message) VALUES (?, ?, ?, ?, ?, ?, ?)"

		if _, err := db.Exec(sql, res.Timestamp, res.UpdatedTime, res.ClusterName, res.HostName, res.HostIP, res.Level, res.Message); err != nil {
			fmt.Errorf("Failed to insert a message (%s)", str)
		}

		if msgPath == "stdout" {
			fmt.Printf("%s", str)
		} else if msgPath != "none" {
			ll.StrToFile(str, msgPath)
		}
	}

	return nil
}

// WatchAlerts Function
func (mc *MySQLClient) WatchAlerts(logPath string) error {
	db := mc.ConnectMySQL()
	defer db.Close()

	mc.WgClient.Add(1)
	defer mc.WgClient.Done()

	for {
		res, err := mc.alertStream.Recv()
		if err != nil {
			fmt.Errorf("Failed to receive an alert (%s)", err.Error())
			break
		}

		arr, _ := json.Marshal(res)
		str := fmt.Sprintf("%s", string(arr))

		sql := "INSERT INTO " + mc.dbAlertTable +
			" (timestamp, updatedTime, clusterName, hostName, namespaceName, podName," +
			" containerID, containerName, hostPid, ppid, pid, uid," +
			" policyName, severity, tags, message, type, source," +
			" operation, resource, data, action, result) VALUES" +
			" (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"

		if _, err := db.Exec(sql, res.Timestamp, res.UpdatedTime, res.ClusterName, res.HostName, res.NamespaceName, res.PodName,
			res.ContainerID, res.ContainerName, res.HostPID, res.PPID, res.PID, res.UID,
			res.PolicyName, res.Severity, res.Tags, res.Message, res.Type, res.Source,
			res.Operation, res.Resource, res.Data, res.Action, res.Result); err != nil {
			fmt.Errorf("Failed to insert an alert (%s)", str)
		}

		if logPath == "stdout" {
			fmt.Println(str)
		} else if logPath != "none" {
			ll.StrToFile(str+"\n", logPath)
		}
	}

	return nil
}

// WatchLogs Function
func (mc *MySQLClient) WatchLogs(logPath string) error {
	db := mc.ConnectMySQL()
	defer db.Close()

	mc.WgClient.Add(1)
	defer mc.WgClient.Done()

	for {
		res, err := mc.logStream.Recv()
		if err != nil {
			fmt.Errorf("Failed to receive a log (%s)", err.Error())
			break
		}

		arr, _ := json.Marshal(res)
		str := fmt.Sprintf("%s", string(arr))

		sql := "INSERT INTO " + mc.dbLogTable +
			" (timestamp, updatedTime, clusterName, hostName, namespaceName, podName," +
			" containerID, containerName, hostPid, ppid, pid, uid," +
			" type, source, operation, resource, data, result) VALUES" +
			" (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"

		if _, err := db.Exec(sql, res.Timestamp, res.UpdatedTime, res.ClusterName, res.HostName, res.NamespaceName, res.PodName,
			res.ContainerID, res.ContainerName, res.HostPID, res.PPID, res.PID, res.UID,
			res.Type, res.Source, res.Operation, res.Resource, res.Data, res.Result); err != nil {
			fmt.Errorf("Failed to insert a system log (%s)", str)
		}

		if logPath == "stdout" {
			fmt.Println(str)
		} else if logPath != "none" {
			ll.StrToFile(str+"\n", logPath)
		}
	}

	return nil
}

// DestroyClient Function
func (mc *MySQLClient) DestroyClient() error {
	if err := mc.conn.Close(); err != nil {
		return err
	}

	mc.WgClient.Wait()

	return nil
}
