// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package util

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/rand"
	"os/exec"
	"regexp"
	"strings"
	"time"

	kins "github.com/kubearmor/kubearmor-client/install"
	kcli "github.com/kubearmor/kubearmor-client/k8s"
	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/remotecommand"
	"k8s.io/kubectl/pkg/scheme"
)

var k8sClient *kcli.Client
var stopChan chan struct{}

func isK8sEnv() bool {
	if k8sClient != nil {
		return true
	}
	cli, err := kcli.ConnectK8sClient()
	if err != nil {
		return false
	}
	k8sClient = cli
	return true
}

func getOptions() kins.Options {
	return kins.Options{
		"kube-system",
		"kubearmor/kubearmor:stable",
		"",
		false,
	}
}

func k8sInstallKubearmor() error {
	err := kins.K8sInstaller(k8sClient, getOptions())
	if err != nil {
		log.Error("failed to install kubearmor err=%s", err)
		return err
	}
	return nil
}

func k8sUninstallKubearmor() {
	err := kins.K8sUninstaller(k8sClient, getOptions())
	if err != nil {
		log.Error("failed to uninstall kubearmor err=%s", err)
		return
	}
}

// ConditionFunc functions that fulfills the condition handling
type ConditionFunc func() (done bool, err error)

func waitForCondition(timeout time.Duration, cf ConditionFunc) error {
	if timeout == 0 { // if no timeout, the current status of the deployment/daemonset is returned
		_, err := cf()
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			flag, err := cf()
			if err != nil {
				return err
			}
			if flag {
				return nil
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	return errors.New("condition not met")
}

func isDaemonSetReady(dsname string, ns string) ConditionFunc {
	return func() (bool, error) {
		dsset, err := k8sClient.K8sClientset.AppsV1().DaemonSets(ns).List(context.Background(), metav1.ListOptions{})
		if err != nil {
			log.Errorf("could not get daemonsets error:%s", err)
			return false, err
		}
		for _, ds := range dsset.Items {
			if dsname == ds.ObjectMeta.Name && ds.Status.NumberReady > 0 {
				return true, nil
			}
		}
		return false, nil
	}
}

func isDeploymentReady(depname string, ns string) ConditionFunc {
	return func() (bool, error) {
		depset, err := k8sClient.K8sClientset.AppsV1().Deployments(ns).List(context.Background(), metav1.ListOptions{})
		if err != nil {
			log.Errorf("could not get deployment. error:%s", err)
			return false, err
		}
		for _, dep := range depset.Items {
			if depname == dep.ObjectMeta.Name && dep.Status.ReadyReplicas == dep.Status.Replicas {
				return true, nil
			}
		}
		return false, nil
	}
}

// K8sDaemonSetCheck Check if the daemonset exists and is ready
func K8sDaemonSetCheck(dsname string, ns string, timeout time.Duration) error {
	return waitForCondition(timeout, isDaemonSetReady(dsname, ns))
}

// K8sDeploymentCheck Check if the deployment exists and is ready
func K8sDeploymentCheck(depname string, ns string, timeout time.Duration) error {
	return waitForCondition(timeout, isDeploymentReady(depname, ns))
}

func annotationsMatch(pod v1.Pod, ants []string) bool {
	if ants == nil || len(ants) <= 0 {
		return true
	}
	for _, ant := range ants {
		kv := strings.Split(ant, ":")
		k := strings.Trim(kv[0], " ")
		antFound := false
		if len(kv) > 1 {
			antFound = pod.Annotations[k] == strings.Trim(kv[1], " ")
		} else {
			antFound = pod.Annotations[k] != ""
		}
		if !antFound {
			return false
		}
	}
	return true
}

// K8sGetPods Check if Pods exists and is/are Running
func K8sGetPods(podstr string, ns string, ants []string, timeout int) ([]string, error) {
	pods := []string{}
	log.Printf("K8sGetPods pod=%s ns=%s ants=%v timeout=%d", podstr, ns, ants, timeout)
	for t := 0; t <= timeout; t++ {
		podList, err := k8sClient.K8sClientset.CoreV1().Pods(ns).List(context.TODO(), metav1.ListOptions{})
		if err != nil {
			log.Errorf("k8s list pods failed. error=%s", err)
			return nil, err
		}
		pods = []string{}
		for _, p := range podList.Items {
			if p.Status.Phase != v1.PodRunning {
				continue
			}
			if p.Status.Reason != "" {
				continue
			}
			if !annotationsMatch(p, ants) {
				continue
			}
			if strings.HasPrefix(p.ObjectMeta.Name, podstr) {
				pods = append(pods, p.ObjectMeta.Name)
			} else if match, _ := regexp.MatchString(podstr, p.ObjectMeta.Name); match {
				pods = append(pods, p.ObjectMeta.Name)
			}
		}
		if timeout == 0 || len(pods) > 0 {
			break
		}
		time.Sleep(1 * time.Second)
	}
	if len(pods) == 0 {
		return nil, errors.New("pod not found")
	}
	log.Printf("found K8sGetPods pods=%v", pods)
	return pods, nil
}

// K8sExecInPod Exec into the pod. Output: stdout, stderr, err
func K8sExecInPod(pod string, ns string, cmd []string) (string, string, error) {
	req := k8sClient.K8sClientset.CoreV1().RESTClient().Post().Resource("pods").Name(pod).Namespace(ns).SubResource("exec")
	option := &v1.PodExecOptions{
		Command: cmd,
		Stdout:  true,
		Stderr:  true,
		TTY:     true,
	}
	req.VersionedParams(
		option,
		scheme.ParameterCodec,
	)
	exec, err := remotecommand.NewSPDYExecutor(k8sClient.Config, "POST", req.URL())
	if err != nil {
		return "", "", err
	}
	buf := &bytes.Buffer{}
	errBuf := &bytes.Buffer{}
	err = exec.Stream(remotecommand.StreamOptions{
		Stdout: buf,
		Stderr: errBuf,
	})
	return buf.String(), errBuf.String(), nil
}

func init() {
	if !isK8sEnv() {
		log.Error("could not find k8s env")
	}
}

/*
func StartKubearmor(k8sMode bool) error {
	if !k8sMode {
		log.Errorf("only k8s mode supported")
		return errors.New("only k8s mode supported")
	}
	err := K8sDaemonSetCheck("kubearmor", "kube-system", 20)
	if err == nil {
		log.Info("kubearmor daemon already executing, skipping install")
		return nil
	}
	log.Println("installing kubearmor")
	err = k8sInstallKubearmor()
	if err != nil {
		log.Errorf("start kubearmor failed error=%s", err)
		return err
	}
	err = K8sDaemonSetCheck("kubearmor", "kube-system", 20)
	if err == nil {
		return nil
	}
	return nil
}
*/

// Kubectl execute
func Kubectl(cmdstr string) (string, error) {
	cmdf := strings.Fields(cmdstr)
	cmd := exec.Command("kubectl", cmdf...)
	sout, err := cmd.Output()
	return string(sout), err
}

// K8sApply execute
func K8sApply(files []string) error {
	for _, f := range files {
		_, err := Kubectl(fmt.Sprintf("apply -f %s", f))
		if err != nil {
			return err
		}
	}
	time.Sleep(1 * time.Second) // this sleep is needed because it takes time to apply the command
	return nil
}

// K8sDelete Delete
func K8sDelete(files []string) error {
	for _, f := range files {
		_, err := Kubectl(fmt.Sprintf("delete -f %s", f))
		if err != nil {
			return err
		}
	}
	return nil
}

// KspDeleteAll Delete all the kubearmor security policies
func KspDeleteAll() {
	sout, err := Kubectl("get ksp -A --no-headers -o custom-columns=:metadata.name,:metadata.namespace")
	if err != nil {
		return
	}
	lines := strings.Split(sout, "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		field := strings.Fields(line)
		Kubectl("delete ksp " + field[0] + " -n " + field[1])
	}
}

// RandString Get Random string
func RandString(n int) string {
	const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}
