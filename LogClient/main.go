package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"os/signal"
	"sync"
	"syscall"

	pb "github.com/accuknox/KubeArmor/protobuf"
	"google.golang.org/grpc"
)

// StopChan Channel
var StopChan chan struct{}

// init Function
func init() {
	StopChan = make(chan struct{})
}

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

// StrToFile Function
func StrToFile(str, destFile string) {
	file, err := os.OpenFile(destFile, os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		fmt.Errorf("Failed to open a file (%s, %s)", destFile, err.Error())
	}
	defer file.Close()

	str = str + "\n"

	_, err = file.WriteString(str)
	if err != nil {
		fmt.Errorf("Failed to write a string into the file (%s, %s)", destFile, err.Error())
	}
}

// NewClient Function
func NewClient(server string) *LogClient {
	lc := &LogClient{}

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
func (lc *LogClient) WatchMessages(msgPath string, raw bool) error {
	lc.WgClient.Add(1)
	defer lc.WgClient.Done()

	for {
		res, err := lc.msgStream.Recv()
		if err != nil {
			fmt.Errorf("Failed to receive a message (%s)", err.Error())
			break
		}

		if msgPath != "stdout" && msgPath != "none" && raw {
			arr, _ := json.Marshal(res)
			StrToFile(string(arr), msgPath)
			continue
		}

		str := fmt.Sprintf("== Message / %s ==\n", res.UpdatedTime)

		str = str + fmt.Sprintf("Source: %s\n", res.Source)
		str = str + fmt.Sprintf("Source IP: %s\n", res.SourceIP)
		str = str + fmt.Sprintf("Level: %s\n", res.Level)
		str = str + fmt.Sprintf("Message: %s\n", res.Message)

		if msgPath == "stdout" {
			fmt.Println(str)
		} else if msgPath != "none" {
			StrToFile(str, msgPath)
		}
	}

	return nil
}

// WatchLogs Function
func (lc *LogClient) WatchLogs(logPath string, raw bool) error {
	lc.WgClient.Add(1)
	defer lc.WgClient.Done()

	for {
		res, err := lc.logStream.Recv()
		if err != nil {
			fmt.Errorf("Failed to receive a log (%s)", err.Error())
			break
		}

		if logPath != "stdout" && logPath != "none" && raw {
			arr, _ := json.Marshal(res)
			StrToFile(string(arr), logPath)
			continue
		}

		str := fmt.Sprintf("== Log / %s ==\n", res.UpdatedTime)

		str = str + fmt.Sprintf("Host Name: %s\n", res.HostName)
		str = str + fmt.Sprintf("Namespace Name: %s\n", res.NamespaceName)
		str = str + fmt.Sprintf("Pod Name: %s\n", res.PodName)
		str = str + fmt.Sprintf("Container ID: %s\n", res.ContainerID)
		str = str + fmt.Sprintf("Container Name: %s\n", res.ContainerName)

		if len(res.PolicyName) > 0 {
			str = str + fmt.Sprintf("Policy Name: %s\n", res.PolicyName)
		}

		if len(res.Severity) > 0 {
			str = str + fmt.Sprintf("Severity: %s\n", res.Severity)
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

		if logPath == "stdout" {
			fmt.Println(str)
		} else if logPath != "none" {
			StrToFile(str, logPath)
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

// ==================== //
// == Signal Handler == //
// ==================== //

// GetOSSigChannel Function
func GetOSSigChannel() chan os.Signal {
	c := make(chan os.Signal, 1)

	signal.Notify(c,
		syscall.SIGKILL,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT,
		os.Interrupt)

	return c
}

// ========== //
// == Main == //
// ========== //

func main() {
	// get arguments
	grpcPtr := flag.String("grpc", "localhost:32767", "gRPC server information (default -> localhost:32767)")
	msgPtr := flag.String("msg", "none", "Output for messages, {File path | stdout | none (default)}")
	logPtr := flag.String("log", "stdout", "Output for logs, {File path | stdout (default) | none}")
	rawPtr := flag.Bool("raw", false, "Raw file format")
	flag.Parse()

	// create a client
	logClient := NewClient(*grpcPtr)
	if logClient == nil {
		fmt.Errorf("Failed to connect to the gRPC server (%s)", *grpcPtr)
		return
	}
	fmt.Printf("Connected to the gRPC server (%s)\n", *grpcPtr)

	// do healthcheck
	if ok := logClient.DoHealthCheck(); !ok {
		fmt.Errorf("Failed to check the liveness of the gRPC server")
		return
	}
	fmt.Println("Checked the liveness of the gRPC server")

	// watch messages
	go logClient.WatchMessages(*msgPtr, *rawPtr)
	fmt.Println("Started to watch messages")

	// watch logs
	go logClient.WatchLogs(*logPtr, *rawPtr)
	fmt.Println("Started to watch logs")

	// listen for interrupt signals
	sigChan := GetOSSigChannel()
	<-sigChan
	close(StopChan)

	// destroy the client
	if err := logClient.DestroyClient(); err != nil {
		fmt.Errorf("Failed to destroy the gRPC client (%s)", err.Error())
		return
	}
	fmt.Println("Destroyed the gRPC client")
}
