// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

// Package cmd is the collection of all the subcommands available in the operator while providing relevant options for the same
package main

import (
	"errors"
	"path/filepath"

	secv1client "github.com/kubearmor/KubeArmor/pkg/KubeArmorController/client/clientset/versioned"
	opv1client "github.com/kubearmor/KubeArmor/pkg/KubeArmorOperator/client/clientset/versioned"
	controllers "github.com/kubearmor/KubeArmor/pkg/KubeArmorOperator/internal/controller"
	"github.com/kubearmor/KubeArmor/pkg/KubeArmorOperator/k8s"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
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
var Secv1Client *secv1client.Clientset
var AnnotateResource bool
var AnnotateExisting bool
var InitDeploy bool
var LogLevel string
var ProviderHostname, ProviderEndpoint string

// Cmd represents the base command when called without any subcommands
var Cmd = &cobra.Command{
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		level, err := zapcore.ParseLevel(LogLevel)
		if err != nil {
			return errors.New("unable to parse log level")
		}
		config := zap.NewProductionConfig()
		config.Level.SetLevel(level)
		log, _ := config.Build()
		Logger = log.Sugar()
		K8sClient = k8s.NewClient(*Logger, KubeConfig)
		ExtClient = k8s.NewExtClient(*Logger, KubeConfig)
		Opv1Client = k8s.NewOpv1Client(*Logger, KubeConfig)
		Secv1Client = k8s.NewSecv1Client(*Logger, KubeConfig)
		//Initialise k8sClient for all child commands to inherit
		if K8sClient == nil {
			return errors.New("couldn't create k8s client")
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		nodeWatcher := controllers.NewClusterWatcher(K8sClient, Logger, ExtClient, Opv1Client, Secv1Client, PathPrefix, DeploymentName, ProviderHostname, ProviderEndpoint, InitDeploy, AnnotateResource, AnnotateExisting)
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
	Cmd.PersistentFlags().StringVar(&ProviderHostname, "providerHostname", "", "IMDS URL hostname for retrieving cluster name")
	Cmd.PersistentFlags().StringVar(&ProviderEndpoint, "providerEndpoint", "", "IMDS URL endpoint for retrieving cluster name")
	// TODO:- set initDeploy to false by default once this change is added to stable
	Cmd.PersistentFlags().BoolVar(&InitDeploy, "initDeploy", true, "Init container deployment")
	Cmd.PersistentFlags().StringVar(&LogLevel, "loglevel", "info", "log level, e.g., debug, info, warn, error")
	Cmd.PersistentFlags().BoolVar(&AnnotateResource, "annotateResource", false, "when true kubearmor annotate k8s resources with apparmor annotation")
	Cmd.PersistentFlags().BoolVar(&AnnotateExisting, "annotateExisting", false, "when true kubearmor-controller restarts and annotates existing resources, with required annotations")

}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	cobra.CheckErr(Cmd.Execute())
}

func main() {
	Execute()
}
