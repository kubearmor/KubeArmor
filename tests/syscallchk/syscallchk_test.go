// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package syscallchk

import (
        "fmt"
        "time"

        . "github.com/kubearmor/karts/util"
        . "github.com/onsi/ginkgo/v2"
        . "github.com/onsi/gomega"
)

var _ = BeforeSuite(func() {

        err := K8sApply([]string{"res/ubuntu.yaml"})
        Expect(err).To(BeNil())

        KspDeleteAll()
})

var _ = AfterSuite(func() {

        err := K8sDelete([]string{"res/ubuntu.yaml"})
        Expect(err).To(BeNil())
})

var _ = Describe("Syscallchk", func() {
	var ub string

	BeforeEach(func(){
		pods, err := K8sGetPods("ubuntu-1-deployment-", "ubuntu-pods", []string{"container.apparmor.security.beta.kubernetes.io/ubuntu-1-container: localhost/kubearmor-ubuntu-pods-ubuntu-1-deployment-ubuntu-1-container"}, 60)
		Expect(err).To(BeNil())
		Expect(len(pods)).To(Equal(1))
		ub=pods[0]
	})

	AfterEach(func(){
		KarmorLogStop()
                KspDeleteAll()
	})
	
	It("Checks for UNLINKAT syscall in logs for rm", func() {
		_, _, err := K8sExecInPod(ub, "ubuntu-pods", []string{"touch","test.tmp"})
		Expect(err).To(BeNil())

		err = KarmorLogStart("system", "ubuntu-pods", "File", ub)
		Expect(err).To(BeNil())

		sout, _, err := K8sExecInPod(ub, "ubuntu-pods", []string{"rm","test.tmp"})        
                Expect(err).To(BeNil())
		fmt.Printf("---START---\n%s---END---\n", sout)

		logs, _, err := KarmorGetLogs(5*time.Second, 1)
		Expect(logs[0].Source).To(Equal("/bin/rm test.tmp"))
                Expect(logs[0].Data).To(MatchRegexp("syscall=SYS_UNLINKAT*"))
	})

	It("Checks for UNLINKAT syscall in logs for rm -rf", func() {
                _, _, err := K8sExecInPod(ub, "ubuntu-pods", []string{"mkdir","testtmp"})
                Expect(err).To(BeNil())

                err = KarmorLogStart("system", "ubuntu-pods", "File", ub)
                Expect(err).To(BeNil())

                sout, _, err := K8sExecInPod(ub, "ubuntu-pods", []string{"rm","-rf","testtmp"})        
                Expect(err).To(BeNil())
                fmt.Printf("---START---\n%s---END---\n", sout)

                logs, _, err := KarmorGetLogs(5*time.Second, 1)
		Expect(logs[0].Source).To(Equal("/bin/rm -rf testtmp"))
                Expect(logs[0].Data).To(MatchRegexp("syscall=SYS_UNLINKAT*")) 
        })
})
