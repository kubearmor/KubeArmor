package unitest_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestUnitest(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Unitest Suite")
}
