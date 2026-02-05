package handlers

import (
	"context"
	"fmt"
	"net/http"

	"github.com/go-logr/logr"
	securityv1 "github.com/kubearmor/KubeArmor/pkg/KubeArmorController/api/security.kubearmor.com/v1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

type PolicyValidator struct {
	Client  client.Client
	Decoder admission.Decoder
	Logger  logr.Logger
}

func (v *PolicyValidator) Handle(ctx context.Context, req admission.Request) admission.Response {
	policy := &securityv1.KubeArmorPolicy{}
	if err := v.Decoder.Decode(req, policy); err != nil {
		return admission.Errored(http.StatusBadRequest, err)
	}

	v.Logger.Info("Validating KubeArmorPolicy", "name", policy.Name, "namespace", policy.Namespace)

	result := securityv1.ValidateKubeArmorPolicy(policy)

	if len(policy.Spec.Selector.MatchLabels) > 0 {
		matchingPods, err := v.countMatchingPods(ctx, policy.Namespace, policy.Spec.Selector.MatchLabels)
		if err != nil {
			v.Logger.Error(err, "Failed to check matching pods")
		} else if matchingPods == 0 {
			result.AddWarning("spec.selector", fmt.Sprintf("no pods currently match selector in namespace '%s'", policy.Namespace))
		}
	}

	if result.HasWarnings() {
		v.Logger.Info("Policy validation warnings",
			"name", policy.Name,
			"namespace", policy.Namespace,
			"warnings", result.WarningMessages())
	}

	if result.HasErrors() {
		v.Logger.Info("Policy validation failed",
			"name", policy.Name,
			"namespace", policy.Namespace,
			"errors", result.ErrorMessages())
		return admission.Denied(fmt.Sprintf("Policy validation failed: %s", result.ErrorMessages()))
	}

	if result.HasWarnings() {
		return admission.Allowed("").WithWarnings(formatWarnings(result.Warnings)...)
	}

	return admission.Allowed("")
}

func (v *PolicyValidator) countMatchingPods(ctx context.Context, namespace string, labels map[string]string) (int, error) {
	podList := &corev1.PodList{}
	listOpts := []client.ListOption{
		client.InNamespace(namespace),
		client.MatchingLabels(labels),
	}
	if err := v.Client.List(ctx, podList, listOpts...); err != nil {
		return 0, err
	}
	return len(podList.Items), nil
}

type ClusterPolicyValidator struct {
	Client  client.Client
	Decoder admission.Decoder
	Logger  logr.Logger
}

func (v *ClusterPolicyValidator) Handle(ctx context.Context, req admission.Request) admission.Response {
	policy := &securityv1.KubeArmorClusterPolicy{}
	if err := v.Decoder.Decode(req, policy); err != nil {
		return admission.Errored(http.StatusBadRequest, err)
	}

	v.Logger.Info("Validating KubeArmorClusterPolicy", "name", policy.Name)

	result := securityv1.ValidateKubeArmorClusterPolicy(policy)

	if result.HasWarnings() {
		v.Logger.Info("ClusterPolicy validation warnings",
			"name", policy.Name,
			"warnings", result.WarningMessages())
	}

	if result.HasErrors() {
		v.Logger.Info("ClusterPolicy validation failed",
			"name", policy.Name,
			"errors", result.ErrorMessages())
		return admission.Denied(fmt.Sprintf("ClusterPolicy validation failed: %s", result.ErrorMessages()))
	}

	if result.HasWarnings() {
		return admission.Allowed("").WithWarnings(formatWarnings(result.Warnings)...)
	}

	return admission.Allowed("")
}

type HostPolicyValidator struct {
	Client  client.Client
	Decoder admission.Decoder
	Logger  logr.Logger
}

func (v *HostPolicyValidator) Handle(ctx context.Context, req admission.Request) admission.Response {
	policy := &securityv1.KubeArmorHostPolicy{}
	if err := v.Decoder.Decode(req, policy); err != nil {
		return admission.Errored(http.StatusBadRequest, err)
	}

	v.Logger.Info("Validating KubeArmorHostPolicy", "name", policy.Name)

	result := securityv1.ValidateKubeArmorHostPolicy(policy)

	if len(policy.Spec.NodeSelector.MatchLabels) > 0 {
		matchingNodes, err := v.countMatchingNodes(ctx, policy.Spec.NodeSelector.MatchLabels)
		if err != nil {
			v.Logger.Error(err, "Failed to check matching nodes")
		} else if matchingNodes == 0 {
			result.AddWarning("spec.nodeSelector", "no nodes currently match selector")
		}
	}

	if result.HasWarnings() {
		v.Logger.Info("HostPolicy validation warnings",
			"name", policy.Name,
			"warnings", result.WarningMessages())
	}

	if result.HasErrors() {
		v.Logger.Info("HostPolicy validation failed",
			"name", policy.Name,
			"errors", result.ErrorMessages())
		return admission.Denied(fmt.Sprintf("HostPolicy validation failed: %s", result.ErrorMessages()))
	}

	if result.HasWarnings() {
		return admission.Allowed("").WithWarnings(formatWarnings(result.Warnings)...)
	}

	return admission.Allowed("")
}

func (v *HostPolicyValidator) countMatchingNodes(ctx context.Context, labels map[string]string) (int, error) {
	nodeList := &corev1.NodeList{}
	listOpts := []client.ListOption{
		client.MatchingLabels(labels),
	}
	if err := v.Client.List(ctx, nodeList, listOpts...); err != nil {
		return 0, err
	}
	return len(nodeList.Items), nil
}

func formatWarnings(warnings []securityv1.ValidationError) []string {
	result := make([]string, len(warnings))
	for i, w := range warnings {
		result[i] = w.Error()
	}
	return result
}
