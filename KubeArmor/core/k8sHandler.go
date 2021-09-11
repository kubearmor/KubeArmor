// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package core

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	rest "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	kg "github.com/kubearmor/KubeArmor/KubeArmor/log"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

// ================= //
// == K8s Handler == //
// ================= //

// K8s Handler
var K8s *K8sHandler

// init Function
func init() {
	K8s = NewK8sHandler()
}

// K8sHandler Structure
type K8sHandler struct {
	K8sClient   *kubernetes.Clientset
	HTTPClient  *http.Client
	WatchClient *http.Client

	K8sToken string
	K8sHost  string
	K8sPort  string
}

// NewK8sHandler Function
func NewK8sHandler() *K8sHandler {
	kh := &K8sHandler{}

	if val, ok := os.LookupEnv("KUBERNETES_SERVICE_HOST"); ok {
		kh.K8sHost = val
	} else {
		kh.K8sHost = "127.0.0.1"
	}

	if val, ok := os.LookupEnv("KUBERNETES_PORT_443_TCP_PORT"); ok {
		kh.K8sPort = val
	} else {
		kh.K8sPort = "8001" // kube-proxy
	}

	kh.HTTPClient = &http.Client{
		Timeout: time.Second * 5,
		// #nosec
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	kh.WatchClient = &http.Client{
		// #nosec
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	return kh
}

// ================ //
// == K8s Client == //
// ================ //

// InitK8sClient Function
func (kh *K8sHandler) InitK8sClient() bool {
	if !kl.IsK8sEnv() { // not Kubernetes
		return false
	}

	if kh.K8sClient == nil {
		if kl.IsInK8sCluster() {
			return kh.InitInclusterAPIClient()
		}
		if kl.IsK8sLocal() {
			return kh.InitLocalAPIClient()
		}
		return false
	}

	return true
}

// InitLocalAPIClient Function
func (kh *K8sHandler) InitLocalAPIClient() bool {
	var kubeconfig *string
	if home := os.Getenv("HOME"); home != "" {
		kubeconfig = flag.String("kubeconfig", filepath.Join(home, ".kube", "config"), "(optional) absolute path to the kubeconfig file")
	} else {
		kubeconfig = flag.String("kubeconfig", "", "absolute path to the kubeconfig file")
	}
	flag.Parse()

	// use the current context in kubeconfig
	config, err := clientcmd.BuildConfigFromFlags("", *kubeconfig)
	if err != nil {
		return false
	}

	// creates the clientset
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return false
	}
	kh.K8sClient = client

	return true
}

// InitInclusterAPIClient Function
func (kh *K8sHandler) InitInclusterAPIClient() bool {
	read, err := ioutil.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		return false
	}
	kh.K8sToken = string(read)

	// create the configuration by token
	kubeConfig := &rest.Config{
		Host:        "https://" + kh.K8sHost + ":" + kh.K8sPort,
		BearerToken: kh.K8sToken,
		// #nosec
		TLSClientConfig: rest.TLSClientConfig{
			Insecure: true,
		},
	}

	client, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		return false
	}
	kh.K8sClient = client

	return true
}

// ============== //
// == API Call == //
// ============== //

// DoRequest Function
func (kh *K8sHandler) DoRequest(cmd string, data interface{}, path string) ([]byte, error) {
	URL := ""

	if kl.IsInK8sCluster() {
		URL = "https://" + kh.K8sHost + ":" + kh.K8sPort
	} else {
		URL = "http://" + kh.K8sHost + ":" + kh.K8sPort
	}

	pbytes, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(cmd, URL+path, bytes.NewBuffer(pbytes))
	if err != nil {
		return nil, err
	}

	if kl.IsInK8sCluster() {
		req.Header.Add("Content-Type", "application/json")
		req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", kh.K8sToken))
	}

	resp, err := kh.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}

	resBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if err := resp.Body.Close(); err != nil {
		kg.Err(err.Error())
	}

	return resBody, nil
}

// ========== //
// == Node == //
// ========== //

// GetContainerRuntime Function
func (kh *K8sHandler) GetContainerRuntime() string {
	if !kl.IsK8sEnv() { // not Kubernetes
		return ""
	}

	// get a host name
	hostName := kl.GetHostName()

	// get a node from k8s api client
	node, err := kh.K8sClient.CoreV1().Nodes().Get(context.Background(), hostName, metav1.GetOptions{})
	if err != nil {
		return "Unknown"
	}

	return node.Status.NodeInfo.ContainerRuntimeVersion
}

// GetNodeIdentities Function
func (kh *K8sHandler) GetNodeIdentities() []string {
	nodeIdentities := []string{}

	if !kl.IsK8sEnv() { // not Kubernetes
		return nodeIdentities
	}

	// get a host name
	hostName := kl.GetHostName()

	// get a node from k8s api client
	node, err := kh.K8sClient.CoreV1().Nodes().Get(context.Background(), hostName, metav1.GetOptions{})
	if err != nil {
		return nodeIdentities
	}

	// add identities
	for k, v := range node.ObjectMeta.Labels {
		nodeIdentities = append(nodeIdentities, k+"="+v)
	}

	return nodeIdentities
}

// ================ //
// == Deployment == //
// ================ //

// PatchDeploymentWithAppArmorAnnotations Function
func (kh *K8sHandler) PatchDeploymentWithAppArmorAnnotations(namespaceName, deploymentName string, appArmorAnnotations map[string]string) error {
	if !kl.IsK8sEnv() { // not Kubernetes
		return nil
	}

	spec := `{"spec":{"template":{"metadata":{"annotations":{"kubearmor-policy":"enabled",`
	count := len(appArmorAnnotations)

	for k, v := range appArmorAnnotations {
		spec = spec + `"container.apparmor.security.beta.kubernetes.io/` + k + `":"localhost/` + v + `"`

		if count > 1 {
			spec = spec + ","
		}

		count--
	}

	spec = spec + `}}}}}`

	_, err := kh.K8sClient.AppsV1().Deployments(namespaceName).Patch(context.Background(), deploymentName, types.StrategicMergePatchType, []byte(spec), metav1.PatchOptions{})
	if err != nil {
		return err
	}

	return nil
}

// ================ //
// == ReplicaSet == //
// ================ //

// GetDeploymentNameControllingReplicaSet Function
func (kh *K8sHandler) GetDeploymentNameControllingReplicaSet(namespaceName, replicaSetName string) string {
	if !kl.IsK8sEnv() { // not Kubernetes
		return ""
	}

	// get replicaSet from k8s api client
	rs, err := kh.K8sClient.AppsV1().ReplicaSets(namespaceName).Get(context.Background(), replicaSetName, metav1.GetOptions{})
	if err != nil {
		return ""
	}

	// check if we have ownerReferences
	if len(rs.ObjectMeta.OwnerReferences) == 0 {
		return ""
	}

	// check if given ownerReferences are for Deployment
	if rs.ObjectMeta.OwnerReferences[0].Kind != "Deployment" {
		return ""
	}

	// return the deployment name
	return rs.ObjectMeta.OwnerReferences[0].Name
}

// ========== //
// == Pods == //
// ========== //

// GetK8sPod Function
func (kh *K8sHandler) GetK8sPod(K8sPods []tp.K8sPod, namespaceName, containerGroupName string) tp.K8sPod {
	for _, pod := range K8sPods {
		if pod.Metadata["namespaceName"] == namespaceName && pod.Metadata["podName"] == containerGroupName {
			return pod
		}
	}

	return tp.K8sPod{}
}

// WatchK8sPods Function
func (kh *K8sHandler) WatchK8sPods() *http.Response {
	if !kl.IsK8sEnv() { // not Kubernetes
		return nil
	}

	if kl.IsInK8sCluster() { // kube-apiserver
		URL := "https://" + kh.K8sHost + ":" + kh.K8sPort + "/api/v1/pods?watch=true"

		req, err := http.NewRequest("GET", URL, nil)
		if err != nil {
			return nil
		}

		req.Header.Add("Content-Type", "application/json")
		req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", kh.K8sToken))

		resp, err := kh.WatchClient.Do(req)
		if err != nil {
			return nil
		}

		return resp
	}

	// kube-proxy (local)
	URL := "http://" + kh.K8sHost + ":" + kh.K8sPort + "/api/v1/pods?watch=true"

	// #nosec
	if resp, err := http.Get(URL); err == nil {
		return resp
	}

	return nil
}

// ====================== //
// == Custom Resources == //
// ====================== //

// CheckCustomResourceDefinition Function
func (kh *K8sHandler) CheckCustomResourceDefinition(resourceName string) bool {
	if !kl.IsK8sEnv() { // not Kubernetes
		return false
	}

	exist := false
	apiGroup := metav1.APIGroup{}

	// check APIGroup
	if resBody, errOut := kh.DoRequest("GET", nil, "/apis"); errOut == nil {
		res := metav1.APIGroupList{}
		if errIn := json.Unmarshal(resBody, &res); errIn == nil {
			for _, group := range res.Groups {
				if group.Name == "security.kubearmor.com" {
					exist = true
					apiGroup = group
					break
				}
			}
		}
	}

	// check APIResource
	if exist {
		if resBody, errOut := kh.DoRequest("GET", nil, "/apis/"+apiGroup.PreferredVersion.GroupVersion); errOut == nil {
			res := metav1.APIResourceList{}
			if errIn := json.Unmarshal(resBody, &res); errIn == nil {
				for _, resource := range res.APIResources {
					if resource.Name == resourceName {
						return true
					}
				}
			}
		}
	}

	return false
}

// WatchK8sSecurityPolicies Function
func (kh *K8sHandler) WatchK8sSecurityPolicies() *http.Response {
	if !kl.IsK8sEnv() { // not Kubernetes
		return nil
	}

	if kl.IsInK8sCluster() {
		URL := "https://" + kh.K8sHost + ":" + kh.K8sPort + "/apis/security.kubearmor.com/v1/kubearmorpolicies?watch=true"

		req, err := http.NewRequest("GET", URL, nil)
		if err != nil {
			return nil
		}

		req.Header.Add("Content-Type", "application/json")
		req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", kh.K8sToken))

		resp, err := kh.WatchClient.Do(req)
		if err != nil {
			return nil
		}

		return resp
	}

	// kube-proxy (local)
	URL := "http://" + kh.K8sHost + ":" + kh.K8sPort + "/apis/security.kubearmor.com/v1/kubearmorpolicies?watch=true"

	// #nosec
	if resp, err := http.Get(URL); err == nil {
		return resp
	}

	return nil
}
