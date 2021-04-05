package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/accuknox/KubeArmor/LogClient/core"
)

// StopChan Channel
var StopChan chan struct{}

// init Function
func init() {
	StopChan = make(chan struct{})
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
	// == //

	// get arguments
	grpcPtr := flag.String("grpc", "localhost:32767", "gRPC server information")
	msgPtr := flag.String("msg", "none", "Output for messages, {File path | stdout | none}")
	logPtr := flag.String("log", "stdout", "Output for logs, {File path | stdout | none}")
	typePtr := flag.String("type", "policy", "Filter for what kinds of logs to receive, {all | policy | system}")
	rawPtr := flag.Bool("raw", false, "Flag to print logs in a raw format")
	flag.Parse()

	if *msgPtr == "none" && *logPtr == "none" {
		flag.PrintDefaults()
		return
	}

	if *typePtr != "all" && *typePtr != "policy" && *typePtr != "system" {
		fmt.Errorf("Type should be 'all', 'policy', or 'system'")
		return
	}

	// == //

	// create a client
	logClient := core.NewClient(*grpcPtr, *msgPtr, *logPtr, *typePtr)
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

	if *msgPtr != "none" {
		// watch messages
		go logClient.WatchMessages(*msgPtr, *rawPtr)
		fmt.Println("Started to watch messages")
	}

	if *logPtr != "none" {
		// watch logs
		go logClient.WatchLogs(*logPtr, *rawPtr)
		fmt.Println("Started to watch logs")
	}

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

	// == //
}
