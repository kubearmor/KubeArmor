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

	"sigs.k8s.io/yaml"

	hsp "github.com/kubearmor/KubeArmor/pkg/KubeArmorHostPolicy/crd"
	ksp "github.com/kubearmor/KubeArmor/pkg/KubeArmorPolicy/crd"
)

func main() {
	envs := []string{"generic", "EKS", "GKE", "docker", "minikube", "microk8s", "k3s"}
	nsPtr := flag.String("namespace", "kube-system", "Namespace")

	flag.Parse()

	var namespace = *nsPtr

	for _, env := range envs {
		v := []interface{}{
			GetServiceAccount(namespace),
			GetClusterRoleBinding(namespace),
			GetRelayService(namespace),
			GetRelayDeployment(namespace),
			GenerateDaemonSet(strings.ToLower(env), namespace),
			GetPolicyManagerService(namespace),
			GetPolicyManagerDeployment(namespace),
			GetHostPolicyManagerService(namespace),
			GetHostPolicyManagerDeployment(namespace),
			ksp.GetCRD(),
			hsp.GetCRD()}

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
