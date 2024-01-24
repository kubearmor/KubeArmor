// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package main

import (
	"flag"
	"log"
	"os"
	"path"
	"strings"

	"github.com/clarketm/json"

	dp "github.com/kubearmor/KubeArmor/deployments/get"

	"sigs.k8s.io/yaml"

	kcrd "github.com/kubearmor/KubeArmor/pkg/KubeArmorController/crd"
)

func main() {
	envs := []string{"generic", "docker", "minikube", "microk8s", "k0s", "k3s", "GKE", "EKS", "BottleRocket", "AKS", "OKE"}
	nsPtr := flag.String("namespace", "kubearmor", "Namespace")

	flag.Parse()

	var namespace = *nsPtr

	for _, env := range envs {
		v := []interface{}{
			// ServiceAccounts
			dp.GetServiceAccount(namespace),
			dp.GetRelayServiceAccount(namespace),
			dp.GetKubeArmorControllerServiceAccount(namespace),

			// Configmap
			dp.GetKubearmorConfigMap(namespace, dp.KubeArmorConfigMapName),

			// CRDs
			kcrd.GetHspCRD(),
			kcrd.GetKspCRD(),

			// ClusterRoles
			dp.GetClusterRole(),
			dp.GetRelayClusterRole(),
			dp.GetKubeArmorControllerClusterRole(),
			dp.GetKubeArmorControllerProxyRole(),
			dp.GetKubeArmorControllerMetricsReaderRole(),

			// ClusterRoleBindings
			dp.GetClusterRoleBinding(namespace),
			dp.GetRelayClusterRoleBinding(namespace),
			dp.GetKubeArmorControllerClusterRoleBinding(namespace),
			dp.GetKubeArmorControllerProxyRoleBinding(namespace),
			dp.GetKubeArmorControllerMetricsReaderRoleBinding(namespace),

			// Roles
			dp.GetKubeArmorControllerLeaderElectionRole(namespace),
			dp.GetKubeArmorControllerLeaderElectionRoleBinding(namespace),

			// Services
			dp.GetRelayService(namespace),
			dp.GetKubeArmorControllerMetricsService(namespace),
			dp.GetKubeArmorControllerWebhookService(namespace),

			// Apps
			dp.GenerateDaemonSet(strings.ToLower(env), namespace),
			dp.GetRelayDeployment(namespace),
			dp.GetKubeArmorControllerDeployment(namespace),
		}

		currDir, err := os.Getwd()
		if err != nil {
			log.Fatal(err)
		}

		f, err := os.Create(path.Join(currDir, env, "kubearmor.yaml"))
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()

		for _, o := range v {
			if err := writeToYAML(f, o); err != nil {
				log.Fatal(err)
			}
		}

		f.Sync()
	}

}

func writeToYAML(f *os.File, o interface{}) error {
	// Use "clarketm/json" to marshal so as to support zero values of structs with omitempty
	j, err := json.Marshal(o)
	if err != nil {
		log.Fatal(err)
	}

	object, err := yaml.JSONToYAML(j)
	if err != nil {
		return err
	}

	_, err = f.Write(append([]byte("---\n"), object...))
	if err != nil {
		return err
	}

	return nil
}
