package k8s

import (
	"os"

	"go.uber.org/zap"
	"k8s.io/client-go/kubernetes"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

func NewClient(log zap.SugaredLogger, kubeconfig string) *kubernetes.Clientset {
	var cfg *rest.Config
	log.Info("Trying to load InCluster configuration")
	inClusterConfig, err := rest.InClusterConfig()
	if err == rest.ErrNotInCluster {
		log.Info("Not inside a k8s Cluser, Loading kubeconfig")
		kubeConfig, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
			&clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfig},
			&clientcmd.ConfigOverrides{}).ClientConfig()
		if err != nil {
			log.Errorf("Could'nt load configuration from kubeconfig Error=%s", err.Error())
			os.Exit(1)
		}
		log.Info("Loaded configuration from kubeconfig")
		cfg = kubeConfig
	} else if err != nil {
		log.Errorf("Could'nt load inCluster configuration Error=%s", err.Error())
		os.Exit(1)

	} else {
		log.Info("Loaded InCluster configuration")
		cfg = inClusterConfig
	}

	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		log.Errorf("Could'nt create k8s clientset Error=%s", err.Error())
		os.Exit(1)
	}

	return client
}
