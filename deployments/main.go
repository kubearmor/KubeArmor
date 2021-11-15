// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package main

import (
	"flag"
	"log"
	"os"
	"path"
	"strings"

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

		v := []interface{}{GetServiceAccount(namespace), GetClusterRoleBinding(namespace), GetRelayService(namespace), GetRelayDeployment(namespace), GenerateDaemonSet(strings.ToLower(env), namespace), GetPolicyManagerService(namespace), GetPolicyManagerDeployment(namespace), GetHostPolicyManagerService(namespace), GetHostPolicyManagerDeployment(namespace), ksp.GetCRD(), hsp.GetCRD()}

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

	object, err := yaml.Marshal(o)
	if err != nil {
		return err
	}

	_, err = f.Write(append([]byte("---\n"), object...))
	if err != nil {
		return err
	}

	return nil
}
