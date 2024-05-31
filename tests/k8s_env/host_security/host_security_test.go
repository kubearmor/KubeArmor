package hostsecurity_test

import (
    "fmt"

    . "github.com/onsi/ginkgo/v2"
    . "github.com/onsi/gomega"
    "github.com/kubearmor/KubeArmor/tests/util"
)

var _ = Describe("Host Security Policies", func() {
    var hspPolicyName string

    BeforeEach(func() {
        // Apply the host security policy
        hspPolicyName = "test-hsp-policy"
        err := util.ApplyHostSecurityPolicy(hspPolicyName)
        Expect(err).To(BeNil())
    })

    AfterEach(func() {
        // Clean up: Delete the applied host security policy
        err := util.DeleteHostSecurityPolicy(hspPolicyName)
        Expect(err).To(BeNil())
    })

    Context("File Access Restrictions", func() {
        It("should deny access to restricted files", func() {
            // Attempt to access a restricted file
            outFile, _, err := util.ExecuteCommandOnHost("cat /etc/shadow")
            Expect(err).NotTo(BeNil())
            fmt.Println("Error:", err)
            fmt.Println("Output:", outFile)
        })

        It("should allow access to permitted files", func() {
            // Attempt to access a permitted file
            outFile, _, err := util.ExecuteCommandOnHost("cat /etc/hosts")
            Expect(err).To(BeNil())
            fmt.Println("Output:", outFile)
        })
    })

    Context("Network Access Restrictions", func() {
        It("should deny access to restricted network protocols", func() {
            // Attempt to make a connection using a restricted network protocol
            out, _, err := util.ExecuteCommandOnHost("curl http://example.com")
            Expect(err).NotTo(BeNil())
            fmt.Println("Error:", err)
            fmt.Println("Output:", out)
        })

        It("should allow access to permitted network protocols", func() {
            // Attempt to make a connection using a permitted network protocol
            out, _, err := util.ExecuteCommandOnHost("curl http://allowed-site.com")
            Expect(err).To(BeNil())
            fmt.Println("Output:", out)
        })
    })

    Context("Process Execution Restrictions", func() {
        It("should deny execution of restricted processes", func() {
            // Attempt to execute a restricted process
            out, _, err := util.ExecuteCommandOnHost("ping -c 1 google.com")
            Expect(err).NotTo(BeNil())
            fmt.Println("Error:", err)
            fmt.Println("Output:", out)
        })

        It("should allow execution of permitted processes", func() {
            // Attempt to execute a permitted process
            out, _, err := util.ExecuteCommandOnHost("ls /")
            Expect(err).To(BeNil())
            fmt.Println("Output:", out)
        })
    })
})
