package common

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestAddCommonAnnotations(t *testing.T) {
	obj := &metav1.ObjectMeta{}
	AddCommonAnnotations(obj)

	// verify that kubearmor-visibility is NOT set.
	if _, ok := obj.Annotations["kubearmor-visibility"]; ok {
		t.Errorf("Expected kubearmor-visibility annotation to NOT be set")
	}

	// verify that kubearmor-policy is set.
	if policy, ok := obj.Annotations["kubearmor-policy"]; !ok || policy != "enabled" {
		t.Errorf("Expected kubearmor-policy to be enabled")
	}
}
