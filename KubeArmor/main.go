package main

import (
	"flag"
	"os"
	"path/filepath"

	"github.com/accuknox/KubeArmor/KubeArmor/core"
	kg "github.com/accuknox/KubeArmor/KubeArmor/log"
)

func main() {
	if os.Geteuid() != 0 {
		kg.Printf("Need to have root privileges to run %s\n", os.Args[0])
		return
	}

	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		kg.Err(err.Error())
		return
	}

	if err := os.Chdir(dir); err != nil {
		kg.Err(err.Error())
		return
	}

	// == //

	portPtr := flag.String("port", "32767", "gRPC port number")
	outputPtr := flag.String("output", "none", "log file path")
	flag.Parse()

	// == //

	core.KubeArmor(*portPtr, *outputPtr)
}
