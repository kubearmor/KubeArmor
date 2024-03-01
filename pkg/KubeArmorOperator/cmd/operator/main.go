// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

// Package cmd is the collection of all the subcommands available in the operator while providing relevant options for the same
package main

import (
	"errors"
	"path/filepath"

	opv1client "github.com/kubearmor/KubeArmor/pkg/KubeArmorOperator/client/clientset/versioned"
	controllers "github.com/kubearmor/KubeArmor/pkg/KubeArmorOperator/internal/controller"
	"github.com/kubearmor/KubeArmor/pkg/KubeArmorOperator/k8s"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	apiextensionsclientset "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/homedir"
)

var K8sClient *kubernetes.Clientset
var Logger *zap.SugaredLogger
var KubeConfig string
var Context string
var LsmOrder string
var PathPrefix string
var DeploymentName string
var ExtClient *apiextensionsclientset.Clientset
var Opv1Client *opv1client.Clientset

// Cmd represents the base command when called without any subcommands
var Cmd = &cobra.Command{
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		log, _ := zap.NewProduction()
		Logger = log.Sugar()
		K8sClient = k8s.NewClient(*Logger, KubeConfig)
		ExtClient = k8s.NewExtClient(*Logger, KubeConfig)
		Opv1Client = k8s.NewOpv1Client(*Logger, KubeConfig)
		//Initialise k8sClient for all child commands to inherit
		if K8sClient == nil {
			return errors.New("couldn't create k8s client")
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		nodeWatcher := controllers.NewClusterWatcher(K8sClient, Logger, ExtClient, Opv1Client, PathPrefix, DeploymentName)
		go nodeWatcher.WatchConfigCrd()
		nodeWatcher.WatchNodes()

	},
	Use:   "kubearmor-operator",
	Short: "An operator to install kubearmor on k8s clusters",
	Long: `An operator to install kubearmor on k8s clusters
	
KubeArmor is a container-aware runtime security enforcement system that
restricts the behavior (such as process execution, file access, and networking
operation) of containers at the system level.
	`,
	SilenceUsage:  true,
	SilenceErrors: true,
}

func init() {
	if home := homedir.HomeDir(); home != "" {
		Cmd.PersistentFlags().StringVar(&KubeConfig, "kubeconfig", filepath.Join(home, ".kube", "config"), "Path to the kubeconfig file to use")
	} else {
		Cmd.PersistentFlags().StringVar(&KubeConfig, "kubeconfig", "", "Path to the kubeconfig file to use")
	}
	Cmd.PersistentFlags().StringVar(&LsmOrder, "lsm", "bpf,apparmor,selinux", "lsm preference order to use")
	Cmd.PersistentFlags().StringVar(&PathPrefix, "pathprefix", "/rootfs/", "path prefix for runtime search")
	Cmd.PersistentFlags().StringVar(&DeploymentName, "deploymentName", "kubearmor-operator", "operator deployment name")
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	cobra.CheckErr(Cmd.Execute())
}

func main() {
	Execute()
}
