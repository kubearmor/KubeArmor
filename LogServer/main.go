package main

import (
	"flag"
	"fmt"

	"github.com/accuknox/KubeArmor/LogServer/core"
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
	server := core.NewLogServer(port)

	// receive logs
	go server.ReceiveLogs()
	core.WgServer.Add(1)

	// listen for interrupt signals
	sigChan := server.GetChan()
	<-sigChan
	fmt.Println("Got a signal to terminate the LogServer")
	server.StopChan()

	// stop server
	server.DestroyLogServer()
}
