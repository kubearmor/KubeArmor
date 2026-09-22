// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

// Package cmd is the collection of all the subcommands available in the operator while providing relevant options for the same
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"os"
	"path/filepath"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	deployments "github.com/kubearmor/KubeArmor/deployments/get"
	securityv1 "github.com/kubearmor/KubeArmor/pkg/KubeArmorOperator/api/security.kubearmor.com/v1"
	"github.com/kubearmor/KubeArmor/pkg/KubeArmorOperator/cmd"
	"github.com/kubearmor/KubeArmor/pkg/KubeArmorOperator/common"
	"github.com/kubearmor/KubeArmor/pkg/KubeArmorOperator/handlers"
	"github.com/kubearmor/KubeArmor/pkg/KubeArmorOperator/informer"
	controllers "github.com/kubearmor/KubeArmor/pkg/KubeArmorOperator/internal/controller"
	"github.com/kubearmor/KubeArmor/pkg/KubeArmorOperator/k8s"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/util/homedir"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/metrics/filters"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
	// +kubebuilder:scaffold:imports
)

var o cmd.OperatorOptions

var (
	scheme = runtime.NewScheme()
)

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

		var tlsOpts []func(*tls.Config)

		// if the enable-http2 flag is false (the default), http/2 should be disabled
		// due to its vulnerabilities. More specifically, disabling http/2 will
		// prevent from being vulnerable to the HTTP/2 Stream Cancellation and
		// Rapid Reset CVEs. For more information see:
		// - https://github.com/advisories/GHSA-qppj-fm5r-hxr3
		// - https://github.com/advisories/GHSA-4374-p667-p6c8
		disableHTTP2 := func(c *tls.Config) {
			o.Logger.Info("disabling http/2")
			c.NextProtos = []string{"http/1.1"}
		}

		if !o.EnableHTTP2 {
			tlsOpts = append(tlsOpts, disableHTTP2)
		}

		certDir := "/tmp/k8s-webhook-server/serving-certs"
		if err := os.MkdirAll(certDir, 0755); err != nil {
			o.Logger.Errorf("FATAL: unable to create cert directory: %v\n", err)
			os.Exit(1)
		}

		sec, err := o.K8sClient.CoreV1().Secrets(common.Namespace).Get(cmd.Context(), deployments.KubeArmorOperatorSecretName, metav1.GetOptions{})

		var tlsCrtBytes, tlsKeyBytes []byte
		if err == nil && len(sec.Data["tls.crt"]) > 0 && len(sec.Data["tls.key"]) > 0 {
			// Secret already exists: REUSE
			o.Logger.Info("Found existing webhook cert secret, reusing keys")
			tlsCrtBytes = sec.Data["tls.crt"]
			tlsKeyBytes = sec.Data["tls.key"]
		} else {
			// Secret does not exist yet: GENERATE
			o.Logger.Info("Generating new webhook PKI")
			caCert, tlsCrt, tlsKey, pkiErr := common.GeneratePki(common.Namespace, deployments.KubeArmorOperatorWebhookServiceName)
			if pkiErr != nil {
				o.Logger.Error(pkiErr, "unable to generate webhook certificates")
				os.Exit(1)
			}
			tlsCrtBytes = tlsCrt.Bytes()
			tlsKeyBytes = tlsKey.Bytes()

			// Save it to a Kubernetes Secret
			newSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      deployments.KubeArmorOperatorSecretName,
					Namespace: common.Namespace,
				},
				Data: map[string][]byte{
					"ca.crt":  caCert.Bytes(),
					"tls.crt": tlsCrtBytes,
					"tls.key": tlsKeyBytes,
				},
			}
			_, err = o.K8sClient.CoreV1().Secrets(common.Namespace).Create(context.TODO(), newSecret, metav1.CreateOptions{})
			if err != nil {
				o.Logger.Error(err, "unable to create webhook secret")
				os.Exit(1)
			}
		}

		// Write the certificate and key files to disk where controller-runtime expects them
		if err := os.WriteFile(filepath.Join(certDir, "tls.crt"), tlsCrtBytes, 0600); err != nil {
			o.Logger.Error(err, "unable to write tls.crt")
			os.Exit(1)
		}
		if err := os.WriteFile(filepath.Join(certDir, "tls.key"), tlsKeyBytes, 0600); err != nil {
			o.Logger.Error(err, "unable to write tls.key")
			os.Exit(1)
		}
		o.Logger.Info("Successfully wrote webhook TLS cert and key to local disk")

		webhookServer := webhook.NewServer(webhook.Options{
			TLSOpts: tlsOpts,
			Port:    o.WebhookPort,
		})

		// Metrics endpoint is enabled in 'config/default/kustomization.yaml'. The Metrics options configure the server.
		// More info:
		// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.19.1/pkg/metrics/server
		// - https://book.kubebuilder.io/reference/metrics.html
		metricsServerOptions := metricsserver.Options{
			BindAddress:   o.MetricsAddr,
			SecureServing: o.SecureMetrics,
			TLSOpts:       tlsOpts,
		}

		if o.SecureMetrics {
			// FilterProvider is used to protect the metrics endpoint with authn/authz.
			// These configurations ensure that only authorized users and service accounts
			// can access the metrics endpoint. The RBAC are configured in 'config/rbac/kustomization.yaml'. More info:
			// https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.19.1/pkg/metrics/filters#WithAuthenticationAndAuthorization
			metricsServerOptions.FilterProvider = filters.WithAuthenticationAndAuthorization

			// TODO(user): If CertDir, CertName, and KeyName are not specified, controller-runtime will automatically
			// generate self-signed certificates for the metrics server. While convenient for development and testing,
			// this setup is not recommended for production.
		}

		mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
			Scheme:                 scheme,
			Metrics:                metricsServerOptions,
			WebhookServer:          webhookServer,
			HealthProbeBindAddress: o.ProbeAddr,
			LeaderElection:         o.EnableLeaderElection,
			LeaderElectionID:       "191ee55f.kubearmor.com",
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
			o.Logger.Error(err, "unable to start manager")
			os.Exit(1)
		}
		o.Logger.Info("DEBUG: creating controller-runtime manager")

		if err = (&controllers.KubeArmorPolicyReconciler{
			Client: mgr.GetClient(),
			Scheme: mgr.GetScheme(),
		}).SetupWithManager(mgr); err != nil {
			o.Logger.Error(err, "FATAL: unable to create KubeArmorPolicy controller")
			os.Exit(1)
		}
		if err = (&controllers.KubeArmorHostPolicyReconciler{
			Client: mgr.GetClient(),
			Scheme: mgr.GetScheme(),
		}).SetupWithManager(mgr); err != nil {
			o.Logger.Error(err, "FATAL: unable to create KubeArmorHostPolicy controller")
			os.Exit(1)
		}

		cluster := informer.InitCluster()
		o.Logger.Info("Starting node watcher")
		go informer.NodeWatcher(o.K8sClient, &cluster, ctrl.Log.WithName("informer").WithName("NodeWatcher"))

		o.Logger.Info("Adding mutation webhook")
		mgr.GetWebhookServer().Register("/mutate-pods", &webhook.Admission{
			Handler: &handlers.PodAnnotator{
				Client:    mgr.GetClient(),
				Logger:    o.Logger,
				Decoder:   admission.NewDecoder(mgr.GetScheme()),
				Cluster:   &cluster,
				ClientSet: o.K8sClient,
			},
		})

		if !o.AnnotateExisting {
			o.Logger.Info("Not annotating existing resources as annotate existing is set to false")
		} else {
			o.Logger.Info("Adding pod refresher controller")
			if err = (&controllers.PodRefresherReconciler{
				Client:           mgr.GetClient(),
				Scheme:           mgr.GetScheme(),
				Cluster:          &cluster,
				ClientSet:        o.K8sClient,
				AnnotateExisting: o.AnnotateExisting,
			}).SetupWithManager(mgr); err != nil {
				o.Logger.Errorf("FATAL: unable to create PodRefresher controller: %v\n", err)
				os.Exit(1)
			}
		}
		// +kubebuilder:scaffold:builder

		if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
			o.Logger.Errorf("unable to set up health check: %v\n", err)
			os.Exit(1)
		}
		if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
			o.Logger.Errorf("unable to set up ready check: %v\n", err)
			os.Exit(1)
		}

		o.Logger.Info("starting manager")
		go func() {
			if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
				o.Logger.Error(err, "FATAL: problem running manager")
				os.Exit(1)
			}
		}()

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
	Cmd.PersistentFlags().BoolVar(&o.AnnotateExisting, "annotateExisting", false, "when true kubearmor-operator restarts and annotates existing resources, with required annotations")
	Cmd.PersistentFlags().StringArrayVar(&o.ImagePullSecrets, "image-pull-secrets", []string{}, "Image pull secrets for pulling KubeArmor images")
	Cmd.PersistentFlags().StringVar(&o.SocketFile, "socket-file", "", "explicit path to CRI socket file (passed to snitch for runtime detection)")

	Cmd.PersistentFlags().StringVar(&o.MetricsAddr, "metrics-bind-address", "0", "The address the metrics endpoint binds to. "+"Use :8443 for HTTPS or :8080 for HTTP, or leave as 0 to disable the metrics service.")
	Cmd.PersistentFlags().BoolVar(&o.EnableLeaderElection, "leader-elect", false, "Enable leader election for controller manager. "+"Enabling this will ensure there is only one active controller manager.")
	Cmd.PersistentFlags().StringVar(&o.ProbeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	Cmd.PersistentFlags().BoolVar(&o.SecureMetrics, "metrics-secure", true, "If set, the metrics endpoint is served securely via HTTPS. Use --metrics-secure=false to use HTTP instead.")
	Cmd.PersistentFlags().BoolVar(&o.EnableHTTP2, "enable-http2", false, "If set, HTTP/2 will be enabled for the metrics and webhook servers")
	Cmd.PersistentFlags().IntVar(&o.WebhookPort, "webhook-port", 9443, "The address the webhook server binds to.")

	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	utilruntime.Must(securityv1.AddToScheme(scheme))
	// +kubebuilder:scaffold:scheme
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	cobra.CheckErr(Cmd.Execute())
}

func main() {
	Execute()
}
