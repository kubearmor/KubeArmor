package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/accuknox/KubeArmor/KubeArmor/core"
)

func main() {
	if os.Geteuid() != 0 {
		fmt.Printf("Need to have root privileges to run %s\n", os.Args[0])
		return
	}

	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		fmt.Printf("%v\n", err)
		return
	}

	if err := os.Chdir(dir); err != nil {
		fmt.Printf("Error: could not move into the directory (%s)\n", dir)
		return
	}

	core.KubeArmor()
}
