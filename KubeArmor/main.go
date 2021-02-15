package main

import (
	"flag"
	"os"
	"path/filepath"

	"log"
	"net/http"
	_ "net/http/pprof"

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
	pprofPtr := flag.String("pprof", "none", "pprof port number")
	flag.Parse()

	if *pprofPtr != "none" {
		go func() {
			log.Println(http.ListenAndServe("0.0.0.0:"+*pprofPtr, nil))
		}()
	}

	// == //

	core.KubeArmor(*portPtr, *outputPtr)
}
