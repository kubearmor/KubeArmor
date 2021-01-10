package server

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"

	pb "github.com/accuknox/KubeArmor/protobuf"
	"google.golang.org/grpc"
)

// Output Mode
var Output bool

// init Function
func init() {
	Output = true
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
			// fmt.Println(err.Error())
			return nil
		}

		if Output {
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
			// fmt.Println(err.Error())
			return nil
		}

		if Output {
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
func NewLogServer(port string) *LogServer {
	ls := new(LogServer)

	// listen to gRPC port
	listener, err := net.Listen("tcp", port)
	if err != nil {
		return nil
	}
	ls.listener = listener

	// create a log server
	ls.logServer = grpc.NewServer()

	// register a log service
	logService := &LogMessage{}
	pb.RegisterLogMessageServer(ls.logServer, logService)

	if Output {
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
func (ls *LogServer) DestroyLogServer() {
	// close listener
	if ls.listener != nil {
		ls.listener.Close()
		ls.listener = nil
	}

	// wait for other routines
	ls.WgServer.Wait()
}
