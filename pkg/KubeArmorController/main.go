// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package main

import (
	"flag"
	"os"
	"path/filepath"
	"strings"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.

	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/go-logr/logr"
	securityv1 "github.com/kubearmor/KubeArmor/pkg/KubeArmorController/api/security.kubearmor.com/v1"
	"github.com/kubearmor/KubeArmor/pkg/KubeArmorController/controllers"
	"github.com/kubearmor/KubeArmor/pkg/KubeArmorController/handlers"
	//+kubebuilder:scaffold:imports
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	utilruntime.Must(securityv1.AddToScheme(scheme))
	//+kubebuilder:scaffold:scheme
}

func main() {
	var metricsAddr string
	var enableLeaderElection bool
	var probeAddr string
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	opts := zap.Options{
		Development: true,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		MetricsBindAddress:     metricsAddr,
		Port:                   9443,
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "5c4b1500.kubearmor.com",
		// LeaderElectionReleaseOnCancel defines if the leader should step down voluntarily
		// when the Manager ends. This requires the binary to immediately end when the
		// Manager is stopped, otherwise, this setting is unsafe. Setting this significantly
		// speeds up voluntary leader transitions as the new leader don't have to wait
		// LeaseDuration time first.
		//
		// In the default scaffold provided, the program ends immediately after
		// the manager stops, so would be fine to enable this option. However,
		// if you are doing or is intended to do any operation such as perform cleanups
		// after the manager stops then its usage might be unsafe.
		// LeaderElectionReleaseOnCancel: true,
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("Adding mutation webhook")
	mgr.GetWebhookServer().Register("/mutate-pods", &webhook.Admission{
		Handler: &handlers.PodAnnotator{
			Client:   mgr.GetClient(),
			Logger:   setupLog,
			Enforcer: detectEnforcer(setupLog),
			Decoder:  admission.NewDecoder(mgr.GetScheme()),
		},
	})

	setupLog.Info("Adding pod refresher controller")
	if err = (&controllers.PodRefresherReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "Pod")
		os.Exit(1)
	}

	setupLog.Info("Adding KubeArmor Host policy controller")
	if err = (&controllers.KubeArmorHostPolicyReconciler{
		Client: mgr.GetClient(),
		Log:    ctrl.Log.WithName("controllers").WithName("KubeArmorHostPolicy"),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "KubeArmorHostPolicy")
		os.Exit(1)
	}

	setupLog.Info("Adding KubeArmor policy controller")
	if err = (&controllers.KubeArmorPolicyReconciler{
		Client: mgr.GetClient(),
		Log:    ctrl.Log.WithName("controllers").WithName("KubeArmorPolicy"),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "KubeArmorPolicy")
		os.Exit(1)
	}

	//+kubebuilder:scaffold:builder

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}

// detect the enforcer on the node
func detectEnforcer(logger logr.Logger) string {
	// assumption: all nodes have the same OSes

	lsm := []byte{}
	lsmPath := "/sys/kernel/security/lsm"

	if _, err := os.Stat(filepath.Clean(lsmPath)); err == nil {
		lsm, err = os.ReadFile(lsmPath)
		if err != nil {
			logger.Info("Failed to read /sys/kernel/security/lsm " + err.Error())
			return ""
		}
	}

	enforcer := string(lsm)

	if strings.Contains(enforcer, "bpf") {
		logger.Info("Detected BPFLSM as the cluster Enforcer")
		return "BPFLSM"
	} else if strings.Contains(enforcer, "apparmor") {
		logger.Info("Detected AppArmor as the cluster Enforcer")
		return "AppArmor"
	} else if strings.Contains(enforcer, "selinux") {
		logger.Info("Detected SELinux as the cluster Enforcer")
		return "SELinux"
	}

	logger.Info("No enforcer was detected")
	return ""
}
