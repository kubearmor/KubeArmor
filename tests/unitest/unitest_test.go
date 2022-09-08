// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package unitest

import (
        "time"
	"regexp"

        . "github.com/kubearmor/karts/util"
        . "github.com/onsi/ginkgo/v2"
        . "github.com/onsi/gomega"
)

var _ = BeforeSuite(func() {
	err := K8sApply([]string{"res/ubuntu.yaml"})
	Expect(err).To(BeNil())
	err = K8sApply([]string{"res/nginx.yaml"})
	Expect(err).To(BeNil())
	time.Sleep(180*time.Second)
	KspDeleteAll()
})

var _ = AfterSuite(func() {
	err := K8sDelete([]string{"res/ubuntu.yaml"})
	Expect(err).To(BeNil())
	err = K8sDelete([]string{"res/nginx.yaml"})
	Expect(err).To(BeNil())
})

var _ = Describe("Unitest", func() {
	var ub string
	var ng string
	var ngip string

	BeforeEach(func(){
		pods, err := K8sGetPods("ubuntu-1-deployment-", "ubuntu-pods", []string{"container.apparmor.security.beta.kubernetes.io/ubuntu-1-container: localhost/kubearmor-ubuntu-pods-ubuntu-1-deployment-ubuntu-1-container"}, 60)
		Expect(err).To(BeNil())
		Expect(len(pods)).To(Equal(1))
		ub=pods[0]
		pods, err = K8sGetPods("nginx-", "nginx-pods", []string{"container.apparmor.security.beta.kubernetes.io/nginx: localhost/kubearmor-nginx-pods-nginx-nginx"}, 60)
		Expect(err).To(BeNil())
		Expect(len(pods)).To(Equal(1))
		ng=pods[0]
		sout, _, err := K8sExecInPod(ng, "nginx-pods", []string{"printenv","MY_POD_IP"})
		Expect(err).To(BeNil())
		ngip = sout[:len(sout)-2]
	})

	AfterEach(func(){
		KarmorLogStop()
		KspDeleteAll()
	})

	It("Checks for RMDIR syscall in logs for rmdir", func() {
                _, _, err := K8sExecInPod(ub, "ubuntu-pods", []string{"mkdir","test"})
                Expect(err).To(BeNil())
                err = KarmorLogStart("system", "ubuntu-pods", "File", ub)
                Expect(err).To(BeNil())
                _, _, err = K8sExecInPod(ub, "ubuntu-pods", []string{"rmdir","test"})
                Expect(err).To(BeNil())
                logs, _, err := KarmorGetLogs(5*time.Second, 50)
                match := false
                for _, log := range logs {
                        match, _ = regexp.MatchString("syscall=SYS_RMDIR*",log.Data)
                        if match {
                                break
                        }
                }
                Expect(match).To(Equal(true))
        })

	It("Checks for UNLINK syscall in logs for unlink", func() {
                _, _, err := K8sExecInPod(ub, "ubuntu-pods", []string{"touch","test.txt"})
                Expect(err).To(BeNil())
                err = KarmorLogStart("system", "ubuntu-pods", "File", ub)
                Expect(err).To(BeNil())
                _, _, err = K8sExecInPod(ub, "ubuntu-pods", []string{"unlink","test.txt"})
                Expect(err).To(BeNil())
                logs, _, err := KarmorGetLogs(5*time.Second, 50)
                match := false
                for _, log := range logs {
                        match, _ = regexp.MatchString("syscall=SYS_UNLINK*",log.Data)
                        if match {
                                break
                        }
                }
                Expect(match).To(Equal(true))
        })

	It("Checks for UNLINKAT syscall in logs for rm", func() {
		_, _, err := K8sExecInPod(ub, "ubuntu-pods", []string{"touch","test.tmp"})
		Expect(err).To(BeNil())
		err = KarmorLogStart("system", "ubuntu-pods", "File", ub)
		Expect(err).To(BeNil())
		_, _, err = K8sExecInPod(ub, "ubuntu-pods", []string{"rm","test.tmp"})
		Expect(err).To(BeNil())
		logs, _, err := KarmorGetLogs(5*time.Second, 50)
		match := false
		for _, log := range logs {
			match, _ = regexp.MatchString("syscall=SYS_UNLINKAT*",log.Data)
			if match {
				break
			}
		}
		Expect(match).To(Equal(true))
        })

	It("Checks for UNLINKAT syscall in logs for rm -rf", func() {
		_, _, err := K8sExecInPod(ub, "ubuntu-pods", []string{"mkdir","testtmp"})
		Expect(err).To(BeNil())
		err = KarmorLogStart("system", "ubuntu-pods", "File", ub)
		Expect(err).To(BeNil())
		_, _, err = K8sExecInPod(ub, "ubuntu-pods", []string{"rm","-rf","testtmp"})
		Expect(err).To(BeNil())
		logs, _, err := KarmorGetLogs(5*time.Second, 50)
		match := false
                for _, log := range logs {
                        match, _ = regexp.MatchString("syscall=SYS_UNLINKAT*",log.Data)
                        if match {
                                break
                        }       
                }
                Expect(match).To(Equal(true))
        })
	
	It("Checks for TCP_CONNECT in logs for curl", func() {
		err := KarmorLogStart("system", "ubuntu-pods", "Network", ub)
		Expect(err).To(BeNil())
		_, _, err = K8sExecInPod(ub, "ubuntu-pods", []string{"curl","http://"+ngip+":80"})
		Expect(err).To(BeNil())
		logs, _, err := KarmorGetLogs(5*time.Second, 50)
		match := false
                for _, log := range logs {
                        match, _ = regexp.MatchString("kprobe=tcp_connect*",log.Data)
                        if match {
                                break
                        }       
                }
                Expect(match).To(Equal(true))
	})

	It("Checks for TCP_ACCEPT in logs for curl", func() {
		err := KarmorLogStart("system", "nginx-pods", "Network", ng)
		Expect(err).To(BeNil())
		_, _, err = K8sExecInPod(ub, "ubuntu-pods", []string{"curl","http://"+ngip+":80"})
		Expect(err).To(BeNil())
		logs, _, err := KarmorGetLogs(5*time.Second, 50)
		match := false
		for _, log := range logs {
                        match, _ = regexp.MatchString("kprobe=tcp_accept*",log.Data)  
                        if match {
                                break
                        }       
                }
                Expect(match).To(Equal(true))
        })

})
