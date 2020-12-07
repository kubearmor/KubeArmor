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
		fmt.Println("AuditLog -> ", res)
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
			fmt.Println(err.Error())
			return nil
		}

		// print system log
		fmt.Println("SystemLog -> ", res)
	}

	// send a reply message
	return stream.SendAndClose(&pb.ReplyMessage{
		Retval: 0,
	})
}

// HealthCheck Function
func (t *LogMessage) HealthCheck(ctx context.Context, nonce *pb.NonceMessage) (*pb.ReplyMessage, error) {
	replyMessage := pb.ReplyMessage{Retval: nonce.Nonce}
	return &replyMessage, nil
}

func main() {
	// ger arguments
	portPtr := flag.String("port", "32768", "gRPC port number (default: 32768)")
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

	fmt.Printf("Started a gRPC Server (%s)", listener.Addr().String())

	// receive logs
	if err := logServer.Serve(listener); err != nil {
		fmt.Println(err.Error())
	}
}
