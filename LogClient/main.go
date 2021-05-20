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
	gRPCPtr := flag.String("gRPC", "localhost:32767", "gRPC server information")
	msgPathPtr := flag.String("msgPath", "none", "Output location for messages, {path|stdout|none}")
	logPathPtr := flag.String("logPath", "stdout", "Output location for alerts and logs, {path|stdout|none}")
	logFilterPtr := flag.String("logFilter", "policy", "Filter for what kinds of alerts and logs to receive, {policy|system|all}")
	jsonPtr := flag.Bool("json", false, "Flag to print alerts and logs in the JSON format")
	flag.Parse()

	if *msgPathPtr == "none" && *logPathPtr == "none" {
		flag.PrintDefaults()
		return
	}

	if *logFilterPtr != "all" && *logFilterPtr != "policy" && *logFilterPtr != "system" {
		flag.PrintDefaults()
		return
	}

	// == //

	// create a client
	logClient := core.NewClient(*gRPCPtr, *msgPathPtr, *logPathPtr, *logFilterPtr)
	if logClient == nil {
		fmt.Errorf("Failed to connect to the gRPC server (%s)", *gRPCPtr)
		return
	}
	fmt.Printf("Created a gRPC client (%s)\n", *gRPCPtr)

	// do healthcheck
	if ok := logClient.DoHealthCheck(); !ok {
		fmt.Errorf("Failed to check the liveness of the gRPC server")
		return
	}
	fmt.Println("Checked the liveness of the gRPC server")

	if *msgPathPtr != "none" {
		// watch messages
		go logClient.WatchMessages(*msgPathPtr, *jsonPtr)
		fmt.Println("Started to watch messages")
	}

	if *logPathPtr != "none" {
		// watch alerts
		go logClient.WatchAlerts(*logPathPtr, *jsonPtr)
		fmt.Println("Started to watch alerts")

		// watch logs
		go logClient.WatchLogs(*logPathPtr, *jsonPtr)
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
