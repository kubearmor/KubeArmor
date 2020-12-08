package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"

	pb "github.com/accuknox/KubeArmor/LogServer/protobuf"
	"google.golang.org/grpc"
)

// LogMessage Structure
type LogMessage struct{}

// == //

// AuditLogs Function
func (t *LogMessage) AuditLogs(stream pb.LogMessage_AuditLogsServer) error {
	for {
		// receive audit log
		res, err := stream.Recv()

		if err == io.EOF { // end of stream
			break
		}

		if err != nil {
			fmt.Println(err.Error())
			return nil
		}

		// print audit log

		fmt.Printf("== Audit Log / %s ==\n", res.UpdatedTime)

		fmt.Printf("Host Name: %s\n", res.HostName)
		fmt.Printf("Container ID: %s\n", res.ContainerID)
		fmt.Printf("Container Name: %s\n", res.ContainerName)

		fmt.Printf("Source: %s\n", res.Source)
		fmt.Printf("Operation: %s\n", res.Operation)
		fmt.Printf("Resource: %s\n", res.Resource)
		fmt.Printf("Action: %s\n", res.Action)
	}

	// send a reply message
	return stream.SendAndClose(&pb.ReplyMessage{
		Retval: 0,
	})
}

// == //

// SystemLogs Function
func (t *LogMessage) SystemLogs(stream pb.LogMessage_SystemLogsServer) error {
	for {
		// receive system log
		res, err := stream.Recv()

		if err == io.EOF { // end of stream
			break
		}

		if err != nil {
			fmt.Println(err.Error())
			return nil
		}

		// print system log

		fmt.Printf("== System Log / %s ==\n", res.UpdatedTime)

		fmt.Printf("Host Name: %s\n", res.HostName)
		fmt.Printf("Container ID: %s\n", res.ContainerID)
		fmt.Printf("Container Name: %s\n", res.ContainerName)

		fmt.Printf("HostPID: %d, PPID: %d, PID: %d, TID: %d, UID: %d\n", res.HostPID, res.PPID, res.PID, res.TID, res.UID)
		fmt.Printf("Comm: %s\n", res.Comm)

		fmt.Printf("Syscall: %s\n", res.Syscall)

		if len(res.Data) > 0 {
			fmt.Printf("Data: %s\n", res.Data)
		}

		fmt.Printf("Retval: %ld\n", res.Retval)

		if len(res.ErrorMessage) > 0 {
			fmt.Printf("ErrorMessage: %s\n", res.ErrorMessage)
		}
	}

	// send a reply message
	return stream.SendAndClose(&pb.ReplyMessage{
		Retval: 0,
	})
}

// == //

// HealthCheck Function
func (t *LogMessage) HealthCheck(ctx context.Context, nonce *pb.NonceMessage) (*pb.ReplyMessage, error) {
	replyMessage := pb.ReplyMessage{Retval: nonce.Nonce}
	return &replyMessage, nil
}

// == //

func main() {
	// ger arguments
	portPtr := flag.String("port", "32767", "gRPC port number (default: 32767)")
	flag.Parse()

	// get gRPC port
	port := fmt.Sprintf(":%s", *portPtr)

	// listen to gRPC port
	listener, err := net.Listen("tcp", port)
	if err != nil {
		return
	}

	// create a log server
	logServer := grpc.NewServer()

	// register a log service
	logService := &LogMessage{}
	pb.RegisterLogMessageServer(logServer, logService)

	fmt.Printf("Started Log Server (%s)\n", listener.Addr().String())

	// receive logs
	if err := logServer.Serve(listener); err != nil {
		fmt.Println(err.Error())
	}
}
