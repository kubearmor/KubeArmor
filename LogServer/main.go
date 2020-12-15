package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	pb "github.com/accuknox/KubeArmor/LogServer/protobuf"
	"google.golang.org/grpc"
)

// StopChan Channel
var StopChan chan struct{}

// WgServer Handler
var WgServer sync.WaitGroup

// Output Mode
var Output bool

// init Function
func init() {
	StopChan = make(chan struct{})
	WgServer = sync.WaitGroup{}
	Output = true
}

// LogServer Structure
type LogServer struct {
	listener  net.Listener
	logServer *grpc.Server
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
			fmt.Println(err.Error())
			return nil
		}

		if Output {
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

		if Output {
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

			fmt.Printf("Retval: %d\n", res.Retval)

			if len(res.ErrorMessage) > 0 {
				fmt.Printf("ErrorMessage: %s\n", res.ErrorMessage)
			}
		}
	}

	// send a reply message
	return stream.SendAndClose(&pb.ReplyMessage{
		Retval: 0,
	})
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

// GetChan Function
func (ls *LogServer) GetChan() chan os.Signal {
	sigChan := GetOSSigChannel()

	select {
	case <-sigChan:
		fmt.Println("Got a signal to terminate the LogServer")
		close(StopChan)

		ls.DestroyLogServer()

		os.Exit(0)
	default:
		time.Sleep(time.Second * 1)
	}

	return sigChan
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

	return ls
}

// DestroyLogServer Function
func (ls *LogServer) DestroyLogServer() {
	// if ls.listener != nil {
	// 	ls.listener.Close()
	// }
}

// ReceiveLogs Function
func (ls *LogServer) ReceiveLogs() {
	defer WgServer.Done()

	// receive logs
	if err := ls.logServer.Serve(ls.listener); err != nil {
		fmt.Println(err.Error())
	}
}

// ========== //
// == Main == //
// ========== //

func main() {
	// ger arguments
	portPtr := flag.String("port", "32767", "gRPC port number (default: 32767)")
	flag.Parse()

	// get gRPC port
	port := fmt.Sprintf(":%s", *portPtr)

	// start server
	server := NewLogServer(port)
	fmt.Printf("Started Log Server (%s)\n", server.listener.Addr().String())

	// receive logs
	go server.ReceiveLogs()
	WgServer.Add(1)

	// listen for interrupt signals
	sigChan := server.GetChan()
	<-sigChan
	fmt.Println("Got a signal to terminate the LogServer")
	close(StopChan)

	// stop server
	server.DestroyLogServer()
}
