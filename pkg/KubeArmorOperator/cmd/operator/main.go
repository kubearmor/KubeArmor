// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package main

import (
	"crypto/tls"
	"flag"
	"os"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	operatorv1 "github.com/kubearmor/KubeArmor/pkg/KubeArmorOperator/api/operator.kubearmor.com/v1"
	operatorv2 "github.com/kubearmor/KubeArmor/pkg/KubeArmorOperator/api/operator.kubearmor.com/v2"
	"github.com/kubearmor/KubeArmor/pkg/KubeArmorOperator/internal/controller"
	//+kubebuilder:scaffold:imports
)

var (
	scheme         = runtime.NewScheme()
	setupLog       = ctrl.Log.WithName("setup")
	operatorConfig = controller.OperatorConfig{}
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	utilruntime.Must(operatorv1.AddToScheme(scheme))
	utilruntime.Must(operatorv2.AddToScheme(scheme))
	//+kubebuilder:scaffold:scheme
}

func main() {
	var metricsAddr string
	var enableLeaderElection bool
	var probeAddr string
	var secureMetrics bool
	var enableHTTP2 bool
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.BoolVar(&secureMetrics, "metrics-secure", false,
		"If set the metrics endpoint is served securely")
	flag.BoolVar(&enableHTTP2, "enable-http2", false,
		"If set, HTTP/2 will be enabled for the metrics and webhook servers")
	// operator configuration flags
	flag.StringVar(&operatorConfig.Version, "version", "", "The helm chart version of the KubeArmor to deploy")
	flag.StringVar(&operatorConfig.Repository, "repository", "https://kubearmor.github.io/charts",
		"The helm chart repository to be used to pull the KubeArmor chart")
	flag.StringVar(&operatorConfig.Directory, "directory", "", "Path to chart directory if local chart is to be used")
	flag.StringVar(&operatorConfig.ChartName, "chart", "kubearmor", "Helm chart release name")
	flag.BoolVar(&operatorConfig.RollbackOnFailure, "rollbackOnFailure", false, "Enable rollback if a release upgrade failed")
	flag.StringVar(&operatorConfig.SnitchPathPrefix, "pathprefix", "/rootfs/", "Path prefix for runtime search")
	flag.StringVar(&operatorConfig.SnitchImage, "snitchImage", "kubearmor/kubearmor-snitch:latest", "Snitch image to be deployed by the operator")
	flag.StringVar(&operatorConfig.SnitchImagePullPolicy, "snitchImagePullPolicy", "IfNotPresent", "Snitch imagePullPolicy [Always|IfNotPresent|Never]")
	flag.StringVar(&operatorConfig.LsmOrder, "lsmOrder", "bpf,apparmor,selinux", "lsm preference order to use")
	flag.BoolVar(&operatorConfig.SkipCRD, "skip-crd", false, "If it is set to true operator will skip installing operator CRD")
	opts := zap.Options{
		Development: true,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	// if the enable-http2 flag is false (the default), http/2 should be disabled
	// due to its vulnerabilities. More specifically, disabling http/2 will
	// prevent from being vulnerable to the HTTP/2 Stream Cancelation and
	// Rapid Reset CVEs. For more information see:
	// - https://github.com/advisories/GHSA-qppj-fm5r-hxr3
	// - https://github.com/advisories/GHSA-4374-p667-p6c8
	disableHTTP2 := func(c *tls.Config) {
		setupLog.Info("disabling http/2")
		c.NextProtos = []string{"http/1.1"}
	}

	tlsOpts := []func(*tls.Config){}
	if !enableHTTP2 {
		tlsOpts = append(tlsOpts, disableHTTP2)
	}

	webhookServer := webhook.NewServer(webhook.Options{
		TLSOpts: tlsOpts,
	})

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme,
		Metrics: metricsserver.Options{
			BindAddress:   metricsAddr,
			SecureServing: secureMetrics,
			TLSOpts:       tlsOpts,
		},
		WebhookServer:          webhookServer,
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "2a5866d3.kubearmor.com",
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

	k8sClientSet, err := kubernetes.NewForConfig(ctrl.GetConfigOrDie())
	if err != nil {
		setupLog.Error(err, "unable to create k8s clientSet")
	}

	// get operator deployment name
	if name := os.Getenv("OPERATOR_DEPLOYMENT_NAME"); name != "" {
		operatorConfig.OperatorDeploymentName = name
	} else {
		operatorConfig.OperatorDeploymentName = "kubearmor-operator"
	}
	// get operator deployment uid
	if uid := os.Getenv("OPERATOR_DEPLOYMENT_UID"); uid != "" {
		operatorConfig.OperatorDeploymentUID = uid
	}
	// get deployment namespace
	if ns := os.Getenv("KUBEARMOR_OPERATOR_NS"); ns != "" {
		operatorConfig.Namespace = ns
	} else {
		operatorConfig.Namespace = "kubearmor"
	}
	// get webhook-service
	if ws := os.Getenv("WEBHOOK_SERVICE"); ws != "" {
		operatorConfig.WebhookService = ws
	} else {
		operatorConfig.WebhookService = "kubearmor-operator-webhook-service"
	}

	operator, err := controller.NewOperator(operatorConfig, mgr.GetClient(), k8sClientSet, mgr)
	if err != nil {
		setupLog.Error(err, "unable to initialize operator")
		os.Exit(1)
	}

	operator.Start()

	// helm config

	// if err = (&controller.KubeArmorConfigReconciler{
	// 	Client: mgr.GetClient(),
	// 	Scheme: mgr.GetScheme(),
	// }).SetupWithManager(mgr); err != nil {
	// 	setupLog.Error(err, "unable to create controller", "controller", "KubeArmorConfig")
	// 	os.Exit(1)
	// }
	// //+kubebuilder:scaffold:builder

	// if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
	// 	setupLog.Error(err, "unable to set up health check")
	// 	os.Exit(1)
	// }
	// if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
	// 	setupLog.Error(err, "unable to set up ready check")
	// 	os.Exit(1)
	// }

	// setupLog.Info("starting manager")
	// if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
	// 	setupLog.Error(err, "problem running manager")
	// 	os.Exit(1)
	// }
}
