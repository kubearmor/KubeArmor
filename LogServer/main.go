package main

import (
	"flag"
	"fmt"

	"github.com/accuknox/KubeArmor/LogServer/server"
)

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
	logServer := server.NewLogServer(port)

	// receive logs
	go logServer.ReceiveLogs()

	// listen for interrupt signals
	sigChan := logServer.GetChan()
	<-sigChan
	fmt.Println("Got a signal to terminate the LogServer")
	logServer.StopChan()

	// stop server
	logServer.DestroyLogServer()
}
