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

	auditPtr := flag.String("audit", "stdout", "{grpc:[domain name/ip address:port] | file:[absolute path] | stdout}")
	systemPtr := flag.String("system", "none", "{grpc:[domain name/ip address:port] | file:[absolute path] | none}")

	flag.Parse()

	// == //

	core.KubeArmor(*auditPtr, *systemPtr)
}
