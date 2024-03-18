// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

// Package snitch is the collection of all the subcommands available in kArmor while providing relevant options for the same
package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/kubearmor/KubeArmor/pkg/KubeArmorOperator/seccomp"

	"github.com/kubearmor/KubeArmor/pkg/KubeArmorOperator/common"
	"github.com/kubearmor/KubeArmor/pkg/KubeArmorOperator/enforcer"
	"github.com/kubearmor/KubeArmor/pkg/KubeArmorOperator/k8s"
	runtimepkg "github.com/kubearmor/KubeArmor/pkg/KubeArmorOperator/runtime"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/homedir"
)

type metadata struct {
	Metadata metadataSpec `json:"metadata"`
}

type metadataSpec struct {
	Labels map[string]string `json:"labels"`
}

var K8sClient *kubernetes.Clientset
var Logger *zap.SugaredLogger
var KubeConfig string
var Context string
var LsmOrder string
var PathPrefix string = "/rootfs"
var NodeName string
var Runtime string

// Cmd represents the base command when called without any subcommands
var Cmd = &cobra.Command{
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		log, _ := zap.NewProduction()
		Logger = log.Sugar()
		K8sClient = k8s.NewClient(*Logger, KubeConfig)
		//Initialise k8sClient for all child commands to inherit
		if K8sClient == nil {
			return errors.New("couldn't create k8s client")
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		Logger.Infof("Running snitch in node %s", NodeName)
		Logger.Infof("lsm order=%s", LsmOrder)
		Logger.Infof("path prefix=%s", PathPrefix)
		Logger.Infof("k8s runtime=%s", Runtime)
		Logger.Infof("KubeConfig path=%s", KubeConfig)
		snitch()

	},
	Use:   "snitch",
	Short: "A CLI Utility to Detect node related information for KubeArmor",
	Long: `CLI Utility to Detect node related information for KubeArmor
	
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
	Cmd.PersistentFlags().StringVar(&NodeName, "nodename", "", "node name to label")
	Cmd.PersistentFlags().StringVar(&PathPrefix, "pathprefix", "/rootfs", "path prefix for runtime search")
	Cmd.PersistentFlags().StringVar(&Runtime, "runtime", "", "runtime detected by k8s")
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the Cmd.
func Execute() {
	cobra.CheckErr(Cmd.Execute())
}

func snitch() {
	order := strings.Split(LsmOrder, ",")

	seccomp.LoadSeccompInNode()

	// Detecting enforcer
	nodeEnforcer := enforcer.DetectEnforcer(order, PathPrefix, *Logger)
	if (nodeEnforcer == "apparmor") && (enforcer.CheckIfApparmorFsPresent(PathPrefix, *Logger) == "no") {
		nodeEnforcer = "NA"
	}
	if nodeEnforcer != "NA" {
		Logger.Infof("Node enforcer is %s", nodeEnforcer)
	} else {
		Logger.Info("Node doesn't supports any KubeArmor Supported Lsm, Enforcement is disabled")
		nodeEnforcer = "none"
	}

	// Detecting runtime
	runtime, socket := runtimepkg.DetectRuntimeViaMap(PathPrefix, Runtime, *Logger)
	if runtime != "NA" {
		Logger.Infof("Detected %s as node runtime, runtime socket=%s", runtime, socket)
	} else {
		// don't throw an error instead print info that no lsm is present
		Logger.Errorf("Not able to detect runtime")
		os.Exit(1)
	}

	// Check BTF support
	btfPresent := enforcer.CheckBtfSupport(PathPrefix, *Logger)
	Logger.Infof("Kernel has BTF: %s", btfPresent)

	patchNode := metadata{}
	patchNode.Metadata.Labels = map[string]string{}
	patchNode.Metadata.Labels[common.RuntimeLabel] = runtime
	patchNode.Metadata.Labels[common.SeccompLabel] = seccomp.CheckIfSeccompProfilePresent()
	patchNode.Metadata.Labels[common.SocketLabel] = strings.ReplaceAll(socket[1:], "/", "_")
	patchNode.Metadata.Labels[common.EnforcerLabel] = nodeEnforcer
	patchNode.Metadata.Labels[common.RandLabel] = rand.String(4)
	patchNode.Metadata.Labels[common.BTFLabel] = btfPresent
	patchNode.Metadata.Labels[common.ApparmorFsLabel] = enforcer.CheckIfApparmorFsPresent(PathPrefix, *Logger)

	if nodeEnforcer == "none" {
		patchNode.Metadata.Labels[common.SecurityFsLabel] = "no"
	} else {
		patchNode.Metadata.Labels[common.SecurityFsLabel] = enforcer.CheckIfSecurityFsPresent(PathPrefix, *Logger)
	}

	patch, err := json.Marshal(patchNode)

	if err != nil {
		Logger.Errorf("Error while marshaling json, error=%s", err.Error())
		os.Exit(1)
	}
	_, err = K8sClient.CoreV1().Nodes().Patch(context.Background(), NodeName, types.MergePatchType, patch, v1.PatchOptions{})
	if err != nil {
		Logger.Errorf("Error while patching node %s error=%s", NodeName, err.Error())
		os.Exit(1)
	} else {
		Logger.Infof("Patched node %s, patch=%s", NodeName, string(patch))
	}
}

func main() {
	Execute()
}
