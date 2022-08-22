package tcpchk_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestTcpchk(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Tcpchk Suite")
}
