package server

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	pb "github.com/accuknox/KubeArmor/protobuf"
	"google.golang.org/grpc"
)

// AuditLogType for audit logs
var AuditLogType string

// AuditLogPath for audit logs
var AuditLogPath string

// SystemLogType for system logs
var SystemLogType string

// SystemLogPath for system logs
var SystemLogPath string

// init Function
func init() {
	AuditLogType = "stdout"
	AuditLogPath = ""

	SystemLogType = "none"
	SystemLogPath = ""
}

// LogServer Structure
type LogServer struct {
	// gRPC listener
	listener net.Listener

	// log server
	logServer *grpc.Server

	// wait group
	WgServer sync.WaitGroup
}

// ========== //
// == Logs == //
// ========== //

// LogMessage Structure
type LogMessage struct{}

// HealthCheck Function
func (t *LogMessage) HealthCheck(ctx context.Context, nonce *pb.NonceMessage) (*pb.ReplyMessage, error) {
	replyMessage := pb.ReplyMessage{Retval: nonce.Nonce}
	return &replyMessage, nil
}

// AuditLogs Function
func (t *LogMessage) AuditLogs(stream pb.LogMessage_AuditLogsServer) error {
	for {
		// receive audit log
		res, err := stream.Recv()

		if err == io.EOF { // end of stream
			break
		}

		if err != nil {
			return nil
		}

		if AuditLogType == "file" {
			// write audit log in an audit path

			file, err := os.OpenFile(AuditLogPath, os.O_WRONLY|os.O_APPEND, 0644)
			if err != nil {
				fmt.Errorf("%v", err)
			}

			str := fmt.Sprintf("== Audit Log / %s ==\n", res.UpdatedTime)

			str = str + fmt.Sprintf("Host Name: %s\n", res.HostName)
			str = str + fmt.Sprintf("Namespace Name: %s\n", res.NamespaceName)
			str = str + fmt.Sprintf("Pod Name: %s\n", res.PodName)
			str = str + fmt.Sprintf("Container ID: %s\n", res.ContainerID)
			str = str + fmt.Sprintf("Container Name: %s\n", res.ContainerName)

			str = str + fmt.Sprintf("Source: %s\n", res.Source)
			str = str + fmt.Sprintf("Operation: %s\n", res.Operation)
			str = str + fmt.Sprintf("Resource: %s\n", res.Resource)
			str = str + fmt.Sprintf("Result: %s\n", res.Result)

			_, err = file.WriteString(str)
			if err != nil {
				fmt.Errorf("%v", err)
			}

			file.Close()
		} else if AuditLogType == "stdout" {
			// print audit log

			fmt.Printf("== Audit Log / %s ==\n", res.UpdatedTime)

			fmt.Printf("Host Name: %s\n", res.HostName)
			fmt.Printf("Namespace Name: %s\n", res.NamespaceName)
			fmt.Printf("Pod Name: %s\n", res.PodName)
			fmt.Printf("Container ID: %s\n", res.ContainerID)
			fmt.Printf("Container Name: %s\n", res.ContainerName)

			fmt.Printf("Source: %s\n", res.Source)
			fmt.Printf("Operation: %s\n", res.Operation)
			fmt.Printf("Resource: %s\n", res.Resource)
			fmt.Printf("Result: %s\n", res.Result)
		}
	}

	// send a reply message
	return stream.SendAndClose(&pb.ReplyMessage{
		Retval: 0,
	})
}

// SystemLogs Function
func (t *LogMessage) SystemLogs(stream pb.LogMessage_SystemLogsServer) error {
	for {
		// receive system log
		res, err := stream.Recv()

		if err == io.EOF { // end of stream
			break
		}

		if err != nil {
			return nil
		}

		if SystemLogType == "file" {
			// write system log in a system path

			file, err := os.OpenFile(SystemLogPath, os.O_WRONLY|os.O_APPEND, 0644)
			if err != nil {
				fmt.Errorf("%v", err)
			}

			str := fmt.Sprintf("== System Log / %s ==\n", res.UpdatedTime)

			str = str + fmt.Sprintf("Host Name: %s\n", res.HostName)
			str = str + fmt.Sprintf("Namespace Name: %s\n", res.NamespaceName)
			str = str + fmt.Sprintf("Pod Name: %s\n", res.PodName)
			str = str + fmt.Sprintf("Container ID: %s\n", res.ContainerID)
			str = str + fmt.Sprintf("Container Name: %s\n", res.ContainerName)

			str = str + fmt.Sprintf("Source: %s\n", res.Source)
			str = str + fmt.Sprintf("Operation: %s\n", res.Operation)
			str = str + fmt.Sprintf("Resource: %s\n", res.Resource)

			if len(res.Args) > 0 {
				str = str + fmt.Sprintf("Arguments: %s\n", res.Args)
			}

			str = str + fmt.Sprintf("Result: %s\n", res.Result)

			_, err = file.WriteString(str)
			if err != nil {
				fmt.Errorf("%v", err)
			}

			file.Close()
		} else if SystemLogType == "stdout" {
			// print system log

			fmt.Printf("== System Log / %s ==\n", res.UpdatedTime)

			fmt.Printf("Host Name: %s\n", res.HostName)
			fmt.Printf("Namespace Name: %s\n", res.NamespaceName)
			fmt.Printf("Pod Name: %s\n", res.PodName)
			fmt.Printf("Container ID: %s\n", res.ContainerID)
			fmt.Printf("Container Name: %s\n", res.ContainerName)

			fmt.Printf("Source: %s\n", res.Source)
			fmt.Printf("Operation: %s\n", res.Operation)
			fmt.Printf("Resource: %s\n", res.Resource)

			if len(res.Args) > 0 {
				fmt.Printf("Arguments: %s\n", res.Args)
			}

			fmt.Printf("Result: %s\n", res.Result)
		}
	}

	// send a reply message
	return stream.SendAndClose(&pb.ReplyMessage{
		Retval: 0,
	})
}

// =============== //
// == LogServer == //
// =============== //

// NewLogServer Function
func NewLogServer(port, auditLogOption, systemLogOption string) *LogServer {
	ls := new(LogServer)

	// listen to gRPC port
	listener, err := net.Listen("tcp", port)
	if err != nil {
		return nil
	}
	ls.listener = listener

	// set Output modes
	auditArgs := strings.Split(auditLogOption, ":")

	AuditLogType = auditArgs[0]
	if AuditLogType == "file" {
		AuditLogPath = auditArgs[1]

		// get the directory part from the path
		dirLog := filepath.Dir(AuditLogPath)

		// create directories
		if err := os.MkdirAll(dirLog, 0755); err != nil {
			fmt.Errorf("Failed to create a target directory (%s)", err.Error())
			return nil
		}

		// create target file
		targetFile, err := os.Create(AuditLogPath)
		if err != nil {
			fmt.Errorf("Failed to create a target file (%s)", err.Error())
			return nil
		}
		targetFile.Close()
	} else {
		AuditLogPath = ""
	}

	systemArgs := strings.Split(systemLogOption, ":")

	SystemLogType = systemArgs[0]
	if SystemLogType == "file" {
		SystemLogPath = systemArgs[1]

		// get the directory part from the path
		dirLog := filepath.Dir(SystemLogPath)

		// create directories
		if err := os.MkdirAll(dirLog, 0755); err != nil {
			fmt.Errorf("Failed to create a target directory (%s)", err.Error())
			return nil
		}

		// create target file
		targetFile, err := os.Create(SystemLogPath)
		if err != nil {
			fmt.Errorf("Failed to create a target file (%s)", err.Error())
			return nil
		}
		targetFile.Close()
	} else {
		SystemLogPath = ""
	}

	// create a log server
	ls.logServer = grpc.NewServer()

	// register a log service
	logService := &LogMessage{}
	pb.RegisterLogMessageServer(ls.logServer, logService)

	if AuditLogType != "none" && SystemLogType != "none" {
		fmt.Printf("Started Log Server (%s)\n", listener.Addr().String())
	}

	// set wait group
	ls.WgServer = sync.WaitGroup{}

	return ls
}

// ReceiveLogs Function
func (ls *LogServer) ReceiveLogs() {
	ls.WgServer.Add(1)
	defer ls.WgServer.Done()

	// receive logs
	ls.logServer.Serve(ls.listener)
}

// DestroyLogServer Function
func (ls *LogServer) DestroyLogServer() error {
	// close listener
	if ls.listener != nil {
		ls.listener.Close()
		ls.listener = nil
	}

	// wait for other routines
	ls.WgServer.Wait()

	if AuditLogType != "none" && SystemLogType != "none" {
		fmt.Println("Stopped Log Server")
	}

	return nil
}
