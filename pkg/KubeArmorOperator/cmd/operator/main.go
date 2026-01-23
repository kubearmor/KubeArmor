// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

// Package cmd is the collection of all the subcommands available in the operator while providing relevant options for the same
package main

import (
	"errors"
	"path/filepath"

	"github.com/kubearmor/KubeArmor/pkg/KubeArmorOperator/cmd"
	controllers "github.com/kubearmor/KubeArmor/pkg/KubeArmorOperator/internal/controller"
	"github.com/kubearmor/KubeArmor/pkg/KubeArmorOperator/k8s"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"k8s.io/client-go/util/homedir"
)

var o cmd.OperatorOptions

// Cmd represents the base command when called without any subcommands
var Cmd = &cobra.Command{
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		level, err := zapcore.ParseLevel(o.LogLevel)
		if err != nil {
			return errors.New("unable to parse log level")
		}
		config := zap.NewProductionConfig()
		config.Level.SetLevel(level)
		log, _ := config.Build()
		o.Logger = log.Sugar()
		o.K8sClient = k8s.NewClient(*o.Logger, o.KubeConfig)
		o.ExtClient = k8s.NewExtClient(*o.Logger, o.KubeConfig)
		o.Opv1Client = k8s.NewOpv1Client(*o.Logger, o.KubeConfig)
		o.Secv1Client = k8s.NewSecv1Client(*o.Logger, o.KubeConfig)
		//Initialise k8sClient for all child commands to inherit
		if o.K8sClient == nil {
			return errors.New("couldn't create k8s client")
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		nodeWatcher := controllers.NewClusterWatcher(&o)
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
		Cmd.PersistentFlags().StringVar(&o.KubeConfig, "kubeconfig", filepath.Join(home, ".kube", "config"), "Path to the kubeconfig file to use")
	} else {
		Cmd.PersistentFlags().StringVar(&o.KubeConfig, "kubeconfig", "", "Path to the kubeconfig file to use")
	}
	Cmd.PersistentFlags().StringVar(&o.LsmOrder, "lsm", "bpf,apparmor,selinux", "lsm preference order to use")
	Cmd.PersistentFlags().StringVar(&o.PathPrefix, "pathprefix", "/rootfs/", "path prefix for runtime search")
	Cmd.PersistentFlags().StringVar(&o.DeploymentName, "deploymentName", "kubearmor-operator", "operator deployment name")
	Cmd.PersistentFlags().StringVar(&o.ProviderHostname, "providerHostname", "", "IMDS URL hostname for retrieving cluster name")
	Cmd.PersistentFlags().StringVar(&o.ProviderEndpoint, "providerEndpoint", "", "IMDS URL endpoint for retrieving cluster name")
	// TODO:- set initDeploy to false by default once this change is added to stable
	Cmd.PersistentFlags().BoolVar(&o.InitDeploy, "initDeploy", true, "Init container deployment")
	Cmd.PersistentFlags().StringVar(&o.LogLevel, "loglevel", "info", "log level, e.g., debug, info, warn, error")
	Cmd.PersistentFlags().BoolVar(&o.AnnotateResource, "annotateResource", false, "when true kubearmor annotate k8s resources with apparmor annotation")
	Cmd.PersistentFlags().BoolVar(&o.AnnotateExisting, "annotateExisting", false, "when true kubearmor-controller restarts and annotates existing resources, with required annotations")
	Cmd.PersistentFlags().StringArrayVar(&o.ImagePullSecrets, "image-pull-secrets", []string{}, "Image pull secrets for pulling KubeArmor images")
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	cobra.CheckErr(Cmd.Execute())
}

func main() {
	Execute()
}
