package main

import (
	"os"
	"path/filepath"

	operator "github.com/kubearmor/KubeArmor/pkg/KubeArmorOperator/cmd/operator"
	snitch "github.com/kubearmor/KubeArmor/pkg/KubeArmorOperator/cmd/snitch-cmd"
	"github.com/spf13/cobra"
)

func main() {
	var command *cobra.Command
	binaryName := filepath.Base(os.Args[0])
	switch binaryName {
	case "snitch":
		command = snitch.Cmd
	case "operator", "kubearmor-operator":
		command = operator.Cmd
	}
	command.Execute()
}
