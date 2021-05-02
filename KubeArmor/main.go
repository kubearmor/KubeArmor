package main

import (
	"flag"
	"log"
	"os"
	"path/filepath"

	"net/http"
	_ "net/http/pprof"

	"github.com/accuknox/KubeArmor/KubeArmor/core"
	kg "github.com/accuknox/KubeArmor/KubeArmor/log"
)

func main() {
	// == //

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

	// options
	gRPCPtr := flag.String("gRPC", "32767", "gRPC port number")
	logPathPtr := flag.String("logPath", "none", "log file path")
	enableAuditdPtr := flag.Bool("enableAuditd", false, "enabling Auditd")
	enableHostPolicyPtr := flag.Bool("enableHostPolicy", false, "enabling host policies")
	enableSystemLogPtr := flag.Bool("enableSystemLog", false, "enabling system logs")

	// profile option
	pprofPtr := flag.String("pprof", "none", "pprof port number")

	flag.Parse()

	if *pprofPtr != "none" {
		go func() {
			log.Println(http.ListenAndServe("0.0.0.0:"+*pprofPtr, nil))
		}()
	}

	// == //

	core.KubeArmor(*gRPCPtr, *logPathPtr, *enableAuditdPtr, *enableHostPolicyPtr, *enableSystemLogPtr)

	// == //
}
