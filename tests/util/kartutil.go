// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package util

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	gomegaTypes "github.com/onsi/gomega/types"

	kcV1 "github.com/kubearmor/KubeArmor/pkg/KubeArmorController/api/security.kubearmor.com/v1"
	kcScheme "github.com/kubearmor/KubeArmor/pkg/KubeArmorController/client/clientset/versioned/scheme"
	kc "github.com/kubearmor/KubeArmor/pkg/KubeArmorController/client/clientset/versioned/typed/security.kubearmor.com/v1"
	pb "github.com/kubearmor/KubeArmor/protobuf"
	kcli "github.com/kubearmor/kubearmor-client/k8s"
	kclient "github.com/kubearmor/kubearmor-client/vm"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/emptypb"
	appsV1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/tools/remotecommand"
	"k8s.io/kubectl/pkg/scheme"
)

var k8sClient *kcli.Client
var kcClient *kc.SecurityV1Client

// ConfigMapData hosts the structure which is used to configure Config Map Data
type ConfigMapData struct {
	GRPC                        string
	Visibility                  string
	Cluster                     string
	DefaultFilePosture          string
	DefaultCapabilitiesPosture  string
	DefaultNetworkPosture       string
	AlertThrottling             string
	MaxAlertPerSec              string
	ThrottleSec                 string
	DropResourceFromProcessLogs string
}

// GetK8sClient function return instance of k8s client
func GetK8sClient() *kcli.Client {
	return k8sClient
}

func connectKcClient() error {
	var kubeconfig string
	var contextName string

	_ = kcV1.AddToScheme(scheme.Scheme)
	restClientGetter := genericclioptions.ConfigFlags{
		Context:    &contextName,
		KubeConfig: &kubeconfig,
	}
	rawKubeConfigLoader := restClientGetter.ToRawKubeConfigLoader()

	config, err := rawKubeConfigLoader.ClientConfig()
	if err != nil {
		return err
	}

	kcClientset, err := kc.NewForConfig(config)
	if err != nil {
		return nil
	}
	_ = kcScheme.AddToScheme(scheme.Scheme)
	kcClient = kcClientset
	return nil
}

func isK8sEnv() bool {
	if k8sClient != nil {
		return true
	}
	cli, err := kcli.ConnectK8sClient()
	if err != nil {
		return false
	}
	k8sClient = cli
	err = connectKcClient()

	return err == nil
}

// NewDefaultConfigMapData returns Config Map Data with KubeArmor defaults set
func NewDefaultConfigMapData() *ConfigMapData {
	data := &ConfigMapData{}
	data.GRPC = "32767"
	data.Visibility = "none"
	data.Cluster = "default"
	data.DefaultFilePosture = "audit"
	data.DefaultCapabilitiesPosture = "audit"
	data.DefaultNetworkPosture = "audit"
	data.AlertThrottling = "false"
	data.MaxAlertPerSec = "10"
	data.ThrottleSec = "30"
	data.DropResourceFromProcessLogs = "false"

	return data
}

// CreateKAConfigMap function
func (data *ConfigMapData) CreateKAConfigMap() error {
	cm := &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ConfigMap",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "kubearmor-config",
			Namespace: "kubearmor",
			Labels: map[string]string{
				"kubearmor-app": "kubearmor-configmap",
			},
		},
		Data: map[string]string{
			"gRPC":                        data.GRPC,
			"cluster":                     data.Cluster,
			"visibility":                  data.Visibility,
			"defaultFilePosture":          data.DefaultFilePosture,
			"defaultCapabilitiesPosture":  data.DefaultCapabilitiesPosture,
			"defaultNetworkPosture":       data.DefaultNetworkPosture,
			"alertThrottling":             data.AlertThrottling,
			"maxAlertPerSec":              data.MaxAlertPerSec,
			"throttleSec":                 data.ThrottleSec,
			"dropResourceFromProcessLogs": data.DropResourceFromProcessLogs,
		},
	}

	_, err := k8sClient.K8sClientset.CoreV1().ConfigMaps("kubearmor").Create(context.Background(), cm, metav1.CreateOptions{})
	if err != nil {
		if !strings.Contains(err.Error(), "already exists") {
			return err
		}
		_, err := k8sClient.K8sClientset.CoreV1().ConfigMaps("kubearmor").Update(context.Background(), cm, metav1.UpdateOptions{})
		if err != nil {
			return err
		}
	}
	return nil
}

// DeleteKAConfigMap function
func DeleteKAConfigMap() error {
	err := k8sClient.K8sClientset.CoreV1().ConfigMaps("kubearmor").Delete(context.Background(), "kubearmor-config", metav1.DeleteOptions{})
	return err
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

func AnnotationsMatch(pod corev1.Pod, ants []string) bool {
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

// AnnotateNS function
func AnnotateNS(name, key, value string) error {
	ns := corev1.Namespace{}
	ns.Annotations = make(map[string]string)
	ns.Annotations[key] = value
	patch, err := json.Marshal(ns)
	if err != nil {
		return err
	}
	_, err = k8sClient.K8sClientset.CoreV1().Namespaces().Patch(context.TODO(), name, types.MergePatchType, patch, metav1.PatchOptions{})
	return err
}

// K8sGetPods Check if Pods exists and is/are Running
func K8sGetPods(podstr string, ns string, ants []string, timeout int) ([]string, error) {
	pods := []string{}
	log.Printf("K8sGetPods pod=%s ns=%s ants=%v timeout=%d", podstr, ns, ants, timeout)
	for t := 0; t <= timeout; t++ {
		podList, err := k8sClient.K8sClientset.CoreV1().Pods(ns).List(context.Background(), metav1.ListOptions{})
		if err != nil {
			log.Errorf("k8s list pods failed. error=%s", err)
			return nil, err
		}
		pods = []string{}
		for _, p := range podList.Items {
			if p.Status.Phase != corev1.PodRunning || p.DeletionTimestamp != nil {
				continue
			}
			if p.Status.Reason != "" {
				continue
			}
			if !AnnotationsMatch(p, ants) {
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
	option := &corev1.PodExecOptions{
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
	exec.Stream(remotecommand.StreamOptions{
		Stdout: buf,
		Stderr: errBuf,
	})
	return buf.String(), errBuf.String(), nil
}

// K8sExecInPodWithContainer Exec into the pod. Output: stdout, stderr, err
func K8sExecInPodWithContainer(pod string, ns string, container string, cmd []string) (string, string, error) {
	req := k8sClient.K8sClientset.CoreV1().RESTClient().Post().Resource("pods").Name(pod).Namespace(ns).SubResource("exec")
	option := &corev1.PodExecOptions{
		Command:   cmd,
		Stdout:    true,
		Stderr:    true,
		TTY:       true,
		Container: container,
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
	exec.Stream(remotecommand.StreamOptions{
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

// DeleteAllHsp delete all the kubearmorhostpolicies
func DeleteAllHsp() error {
	hsp, err := kcClient.KubeArmorHostPolicies().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		if strings.Contains(err.Error(), "No resource found") {
			return nil
		}
		return err
	}
	for _, h := range hsp.Items {
		err = kcClient.KubeArmorHostPolicies().Delete(context.TODO(), h.Name, metav1.DeleteOptions{})
		if err != nil {
			log.Errorf("error deleting hsp %s", h.Name)
			return err
		}
		log.Printf("deleted hsp %s ", h.Name)
	}
	return nil
}

// DeleteAllCsp delete all the kubearmorclusterpolicies
func DeleteAllCsp() error {
	csp, err := k8sClient.KSPClientset.KubeArmorClusterPolicies().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		if strings.Contains(err.Error(), "No resource found") {
			log.Printf("err %v", err)
		}
		return err
	}
	for _, k := range csp.Items {
		err = k8sClient.KSPClientset.KubeArmorClusterPolicies().Delete(context.TODO(), k.Name, metav1.DeleteOptions{})
		if err != nil {
			log.Errorf("error deleting csp %s", k.Name)
			return err
		}
		log.Printf("deleted csp %s ", k.Name)
	}
	return nil
}

// DeleteAllKsp delete all the kubearmorpolicies from all namespaces
func DeleteAllKsp() error {
	namespaces, err := k8sClient.K8sClientset.CoreV1().Namespaces().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		log.Errorf("error getting namespaces %v", err.Error())
		return err
	}

	for _, ns := range namespaces.Items {
		ksp, err := k8sClient.KSPClientset.KubeArmorPolicies(ns.Name).List(context.TODO(), metav1.ListOptions{})
		if err != nil {
			if strings.Contains(err.Error(), "No resource found") {
				continue
			}
			return err
		}
		for _, k := range ksp.Items {
			err = k8sClient.KSPClientset.KubeArmorPolicies(ns.Name).Delete(context.TODO(), k.Name, metav1.DeleteOptions{})
			if err != nil {
				log.Errorf("error deleting ksp %s in the namespace %s", k.Name, ns.Name)
				return err
			}
			log.Printf("deleted ksp %s in the namespace %s", k.Name, ns.Name)
		}
	}

	return nil
}

// K8sApplyFile can apply deployments, services, namespace, and kubearmorhostpolicy
func K8sApplyFile(fileName string) error {
	f, err := os.ReadFile(fileName)

	if err != nil {
		log.Errorf("error reading file %v", err.Error())
		return err
	}
	// register ksp scheme
	err = kcScheme.AddToScheme(scheme.Scheme)
	if err != nil {
		log.Errorf("unable to register ksp scheme error= %s", err)
		return err
	}

	// multiple yaml files seperate by ---
	fileAsString := string(f[:])
	sepYamlfiles := strings.Split(fileAsString, "---")

	for _, f := range sepYamlfiles {
		if f == "\n" || f == "" {
			// ignore empty cases
			continue
		}

		decode := scheme.Codecs.UniversalDeserializer().Decode
		obj, _, err := decode([]byte(f), nil, nil)
		if err != nil {
			log.Errorf("unable to decode yaml error=%s", err)
			return err
		}
		switch obj := obj.(type) {
		case *appsV1.Deployment:
			deployment := obj
			namespace := deployment.Namespace

			result, err := k8sClient.K8sClientset.AppsV1().Deployments(namespace).Create(context.TODO(), deployment, metav1.CreateOptions{})
			if err != nil {
				if strings.Contains(err.Error(), "already exists") {
					log.Printf("Deployment %s already exists ...", deployment.Name)
					continue
				}
				return err
			}
			log.Printf("Created Deployment %q", result.GetObjectMeta().GetName())

		case *kcV1.KubeArmorPolicy:
			ksp := obj

			ksp.Spec.Capabilities = kcV1.CapabilitiesType{
				MatchCapabilities: append([]kcV1.MatchCapabilitiesType{}, ksp.Spec.Capabilities.MatchCapabilities...),
			}
			ksp.Spec.Network = kcV1.NetworkType{
				MatchProtocols: append([]kcV1.MatchNetworkProtocolType{}, ksp.Spec.Network.MatchProtocols...),
			}

			result, err := k8sClient.KSPClientset.KubeArmorPolicies(ksp.Namespace).Create(context.TODO(), ksp, metav1.CreateOptions{})
			if err != nil {
				if strings.Contains(err.Error(), "already exists") {
					log.Printf("Policy %s already exists ...", ksp.Name)
					continue
				}
				return err
			}
			log.Printf("Created policy %q", result.GetObjectMeta().GetName())
		case *kcV1.KubeArmorClusterPolicy:
			csp := obj

			csp.Spec.Capabilities = kcV1.CapabilitiesType{
				MatchCapabilities: append([]kcV1.MatchCapabilitiesType{}, csp.Spec.Capabilities.MatchCapabilities...),
			}
			csp.Spec.Network = kcV1.NetworkType{
				MatchProtocols: append([]kcV1.MatchNetworkProtocolType{}, csp.Spec.Network.MatchProtocols...),
			}

			result, err := k8sClient.KSPClientset.KubeArmorClusterPolicies().Create(context.TODO(), csp, metav1.CreateOptions{})
			if err != nil {
				if strings.Contains(err.Error(), "already exists") {
					log.Printf("Policy %s already exists ...", csp.Name)
					continue
				}
				return err
			}
			log.Printf("Created policy %q", result.GetObjectMeta().GetName())
		case *corev1.Service:
			svc := obj
			ns := svc.Namespace

			_, err := k8sClient.K8sClientset.CoreV1().Services(ns).Create(context.TODO(), svc, metav1.CreateOptions{})

			if err != nil {
				if strings.Contains(err.Error(), "port is already allocated") {
					sv, err := k8sClient.K8sClientset.CoreV1().Services(ns).Get(context.TODO(), svc.Name, metav1.GetOptions{})
					if err != nil {
						return err
					}
					if sv.Name == svc.Name && sv.Namespace == svc.Namespace {
						log.Printf("Service %s already exists...", svc.Name)
						continue
					}
				}
				if strings.Contains(err.Error(), "already exists") {
					log.Printf("Service %s already exists ...", svc.Name)
					continue
				}
				return err
			}
			log.Printf("Service %s created ...", svc.Name)
		case *corev1.Namespace:
			ns := obj
			_, err := k8sClient.K8sClientset.CoreV1().Namespaces().Create(context.TODO(), ns, metav1.CreateOptions{})
			if err != nil {
				if strings.Contains(err.Error(), "already exists") {
					log.Printf("Namespace %s already exists ...", ns.Name)
					continue
				}
				return err
			}
			log.Printf("Namespace %s created ...", ns.Name)
		case *kcV1.KubeArmorHostPolicy:
			hsp := obj

			hsp.Spec.Capabilities = kcV1.HostCapabilitiesType{
				MatchCapabilities: append([]kcV1.MatchHostCapabilitiesType{}, hsp.Spec.Capabilities.MatchCapabilities...),
			}
			hsp.Spec.Network = kcV1.HostNetworkType{
				MatchProtocols: append([]kcV1.MatchHostNetworkProtocolType{}, hsp.Spec.Network.MatchProtocols...),
			}

			result, err := kcClient.KubeArmorHostPolicies().Create(context.TODO(), hsp, metav1.CreateOptions{})
			if err != nil {
				if strings.Contains(err.Error(), "already exists") {
					log.Printf("Policy %s already exists ...", hsp.Name)
					continue
				}
				return err
			}
			log.Printf("Created policy %q", result.GetObjectMeta().GetName())
		}
	}
	// waiting for a policy to be created is better
	// as it implicitly gives us waiting for old policy to be deleted also
	time.Sleep(5 * time.Second)
	return nil
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

// K8sRuntimeEnforcer extracts Runtime Enforcer from the Node Labels
func K8sRuntimeEnforcer() string {
	nodes, _ := k8sClient.K8sClientset.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
	if len(nodes.Items) <= 0 {
		return ""
	}

	runtimeEnforcer := nodes.Items[0].Labels["kubearmor.io/enforcer"]
	return runtimeEnforcer
}

func K8sRuntime() string {
	nodes, _ := k8sClient.K8sClientset.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
	if len(nodes.Items) <= 0 {
		return ""
	}
	runtime := nodes.Items[0].Status.NodeInfo.ContainerRuntimeVersion
	splitStr := strings.Split(runtime, "://")
	return splitStr[0]
}

// RunDockerCommand() executes docker commmands
func RunDockerCommand(cmdstr string) (string, error) {
	cmdf := strings.Fields(cmdstr)
	cmd := exec.Command("docker", cmdf...)
	sout, err := cmd.Output()
	return string(sout), err
}

func AssertCommand(wp string, namespace string, cmd []string, match gomegaTypes.GomegaMatcher, eventual bool) {
	if eventual {
		Eventually(func() string {
			sout, _, err := K8sExecInPod(wp, namespace, cmd)
			Expect(err).To(BeNil())
			fmt.Printf("---START---\n%s---END---\n", sout)
			return sout
		}, 10*time.Second, 2*time.Second).Should(match)
	} else {
		sout, _, err := K8sExecInPod(wp, namespace, cmd)
		Expect(err).To(BeNil())
		fmt.Printf("---START---\n%s---END---\n", sout)
		Expect(sout).To(match)
	}
}

// SendPolicy sends kubearmor policy using grpc client
func SendPolicy(eventType, path string) error {
	var policyOptions kclient.PolicyOptions
	err := kclient.PolicyHandling(eventType, path, policyOptions)

	return err
}

// ContainerInfo function receives container info from kuberamor in nonk8s mode using grpc client
func ContainerInfo() (*pb.ProbeResponse, error) {
	gRPC := ""

	if val, ok := os.LookupEnv("KUBEARMOR_SERVICE"); ok {
		gRPC = val
	} else {
		gRPC = "localhost:32767"
	}

	conn, err := grpc.NewClient(gRPC, grpc.DialOption(grpc.WithTransportCredentials(insecure.NewCredentials())))
	if err != nil {
		return nil, err
	}

	client := pb.NewProbeServiceClient(conn)

	resp, err := client.GetProbeData(context.Background(), &emptypb.Empty{})

	if err != nil {
		return nil, err
	}
	return resp, nil
}
