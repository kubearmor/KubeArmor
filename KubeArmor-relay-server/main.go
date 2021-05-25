package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/accuknox/KubeArmor/KubeArmor-relay-server/core"
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
	gRPCPortPtr := flag.String("gRPCPort", "32767", "gRPC port")
	flag.Parse()

	// == //

	// create a client
	relayServer := core.NewRelayServer(*gRPCPortPtr)
	if relayServer == nil {
		fmt.Errorf("Failed to create a relay server (:%s)", *gRPCPortPtr)
		return
	}
	fmt.Printf("Created a relay server (:%s)\n", *gRPCPortPtr)

	// serve log feeds
	go relayServer.ServeLogFeeds()
	fmt.Println("Started to serve gRPC-based log feeds")

	// get log feeds
	go relayServer.GetFeedsFromNodes()
	fmt.Println("Started to receive log feeds from each node")

	// listen for interrupt signals
	sigChan := GetOSSigChannel()
	<-sigChan
	close(StopChan)

	// destroy the client
	if err := relayServer.DestroyRelayServer(); err != nil {
		fmt.Errorf("Failed to destroy the relay server (%s)", err.Error())
		return
	}
	fmt.Println("Destroyed the relay server")

	// == //
}
