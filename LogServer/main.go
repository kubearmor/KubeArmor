package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/accuknox/KubeArmor/LogServer/server"
)

// StopChan Channel
var StopChan chan struct{}

// LogServer Handler
var LogServer *server.LogServer

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
	// ger arguments
	portPtr := flag.String("port", "32767", "gRPC port number (default: 32767)")
	auditLogOptionPtr := flag.String("audit", "stdout", "file:[absolute path] | stdout}")
	systemLogOptionPtr := flag.String("system", "none", "file:[absolute path] | stdout | none}")
	flag.Parse()

	// get gRPC port
	port := fmt.Sprintf(":%s", *portPtr)

	// start server
	LogServer = server.NewLogServer(port, *auditLogOptionPtr, *systemLogOptionPtr)

	// receive logs
	go LogServer.ReceiveLogs()

	// listen for interrupt signals
	sigChan := GetOSSigChannel()
	<-sigChan
	fmt.Println("Got a signal to terminate the LogServer")
	close(StopChan)

	// stop server
	LogServer.DestroyLogServer()
}
