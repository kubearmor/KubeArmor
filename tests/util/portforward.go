// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package util

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/transport/spdy"
)

// PortForwardOpt port forwarding options
type PortForwardOpt struct {
	LocalPort   int
	RemotePort  int
	ServiceName string
	Namespace   string
}

// K8sPortForward enable port forwarding
func K8sPortForward(pf PortForwardOpt) (chan struct{}, error) {
	roundTripper, upgrader, err := spdy.RoundTripperFor(k8sClient.Config)
	if err != nil {
		log.Errorf("unable to spdy.RoundTripperFor error=%s", err.Error())
		return nil, err
	}

	path := fmt.Sprintf("/api/v1/namespaces/%s/pods/%s/portforward", pf.Namespace, pf.ServiceName)
	hostIP := strings.TrimLeft(k8sClient.Config.Host, "https:/")
	serverURL := url.URL{Scheme: "https", Path: path, Host: hostIP}

	dialer := spdy.NewDialer(upgrader, &http.Client{Transport: roundTripper}, http.MethodPost, &serverURL)

	stopChan, readyChan := make(chan struct{}, 1), make(chan struct{}, 1)
	out, errOut := new(bytes.Buffer), new(bytes.Buffer)

	forwarder, err := portforward.New(dialer, []string{fmt.Sprintf("%d:%d", pf.LocalPort, pf.RemotePort)},
		stopChan, readyChan, out, errOut)
	if err != nil {
		log.Errorf("unable to portforward. error=%s", err.Error())
		return nil, err
	}

	go func() {
		for range readyChan { // Kubernetes will close this channel when it has something to tell us.
		}
		if len(errOut.String()) != 0 {
			panic(errOut.String())
		} else if len(out.String()) != 0 {
			fmt.Println(out.String())
		}
	}()

	go func() {
		if err = forwarder.ForwardPorts(); err != nil { // Locks until stopChan is closed.
			log.Errorf("unable to ForwardPorts. error=%s", err.Error())
		}
	}()
	time.Sleep(100 * time.Millisecond)
	return stopChan, nil
}

// KubearmorPortForward enable port forwarding for kubearmor
func KubearmorPortForward() error {
	if stopChan != nil {
		log.Error("kubearmor port forward is already in progress")
		return errors.New("kubearmor port forward is already in progress")
	}
	ns := "kubearmor"
	pods, err := K8sGetPods("^kubearmor-.....$", ns, nil, 0)
	if err != nil {
		log.Printf("could not get kubearmor pods assuming process mode")
		return nil
	}
	if len(pods) != 1 {
		log.Errorf("len(pods)=%d", len(pods))
		return errors.New("expecting one kubearmor pod only")
	}
	//	log.Printf("found kubearmor pod:[%s]", pods[0])
	c, err := K8sPortForward(PortForwardOpt{
		LocalPort:   32767,
		RemotePort:  32767,
		ServiceName: pods[0],
		Namespace:   ns})
	if err != nil {
		log.Errorf("could not do kubearmor portforward Error=%s", err.Error())
		return err
	}
	stopChan = c
	return nil
}

// KubearmorPortForwardStop stop kubearmor port forwarding
func KubearmorPortForwardStop() {
	if stopChan == nil {
		return
	}
	close(stopChan)
	stopChan = nil
}
