// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package main

import (
	"os"

	operator "github.com/kubearmor/KubeArmor/pkg/KubeArmorOperator/cmd/operator"
	snitch "github.com/kubearmor/KubeArmor/pkg/KubeArmorOperator/cmd/snitch-cmd"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var Logger *zap.SugaredLogger

var rootCmd = &cobra.Command{
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		log, err := zap.NewProduction()
		if err != nil {
			return err
		}
		Logger = log.Sugar()
		return nil
	},
	Use:   "operator",
	Short: "A CLI utility to install kubearmor-operator or snitch on k8s cluster",
	Long:  "A CLI utility to install kubearmor-operator or snitch on k8s cluster",
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		Logger.Error(err)
		os.Exit(1)
	}
}

func main() {
	Execute()
}

func init() {
	rootCmd.AddCommand(snitch.Cmd)
	rootCmd.AddCommand(operator.Cmd)
}
