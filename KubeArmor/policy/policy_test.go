// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package policy

import (
	"context"
	"encoding/json"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
	pb "github.com/kubearmor/KubeArmor/protobuf"
)

// Mock functions for testing
func mockUpdateContainerPolicySuccess(event tp.K8sKubeArmorPolicyEvent) pb.PolicyStatus {
	return pb.PolicyStatus_Applied
}

func mockUpdateContainerPolicyFailure(event tp.K8sKubeArmorPolicyEvent) pb.PolicyStatus {
	return pb.PolicyStatus_Invalid // Using Invalid instead of Failed
}

func mockUpdateHostPolicySuccess(event tp.K8sKubeArmorHostPolicyEvent) pb.PolicyStatus {
	return pb.PolicyStatus_Applied
}

func mockUpdateHostPolicyFailure(event tp.K8sKubeArmorHostPolicyEvent) pb.PolicyStatus {
	return pb.PolicyStatus_Invalid // Using Invalid instead of Failed
}

// Test data generators
func createValidContainerPolicyData() []byte {
	event := tp.K8sKubeArmorPolicyEvent{
		Object: tp.K8sKubeArmorPolicy{
			Metadata: metav1.ObjectMeta{
				Name: "test-container-policy",
			},
		},
	}
	data, _ := json.Marshal(event)
	return data
}

func createEmptyContainerPolicyData() []byte {
	event := tp.K8sKubeArmorPolicyEvent{
		Object: tp.K8sKubeArmorPolicy{
			Metadata: metav1.ObjectMeta{
				Name: "",
			},
		},
	}
	data, _ := json.Marshal(event)
	return data
}

func createValidHostPolicyData() []byte {
	event := tp.K8sKubeArmorHostPolicyEvent{
		Object: tp.K8sKubeArmorHostPolicy{
			Metadata: metav1.ObjectMeta{
				Name: "test-host-policy",
			},
		},
	}
	data, _ := json.Marshal(event)
	return data
}

func createEmptyHostPolicyData() []byte {
	event := tp.K8sKubeArmorHostPolicyEvent{
		Object: tp.K8sKubeArmorHostPolicy{
			Metadata: metav1.ObjectMeta{
				Name: "",
			},
		},
	}
	data, _ := json.Marshal(event)
	return data
}

func TestPolicyServer_ContainerPolicy(t *testing.T) {
	testCases := []struct {
		name                   string
		containerPolicyEnabled bool
		updateFunction         func(tp.K8sKubeArmorPolicyEvent) pb.PolicyStatus
		policyData             []byte
		invalidJSON            bool
		expectedStatus         pb.PolicyStatus
		expectedError          bool
	}{
		{
			name:                   "Container policy disabled",
			containerPolicyEnabled: false,
			updateFunction:         mockUpdateContainerPolicySuccess,
			policyData:             createValidContainerPolicyData(),
			expectedStatus:         pb.PolicyStatus_NotEnabled,
			expectedError:          false,
		},
		{
			name:                   "Valid container policy - success",
			containerPolicyEnabled: true,
			updateFunction:         mockUpdateContainerPolicySuccess,
			policyData:             createValidContainerPolicyData(),
			expectedStatus:         pb.PolicyStatus_Applied,
			expectedError:          false,
		},
		{
			name:                   "Valid container policy - failure",
			containerPolicyEnabled: true,
			updateFunction:         mockUpdateContainerPolicyFailure,
			policyData:             createValidContainerPolicyData(),
			expectedStatus:         pb.PolicyStatus_Invalid,
			expectedError:          false,
		},
		{
			name:                   "Empty container policy name",
			containerPolicyEnabled: true,
			updateFunction:         mockUpdateContainerPolicySuccess,
			policyData:             createEmptyContainerPolicyData(),
			expectedStatus:         pb.PolicyStatus_Invalid,
			expectedError:          false,
		},
		{
			name:                   "Invalid JSON data",
			containerPolicyEnabled: true,
			updateFunction:         mockUpdateContainerPolicySuccess,
			policyData:             []byte("invalid json"),
			invalidJSON:            true,
			expectedStatus:         pb.PolicyStatus_Invalid,
			expectedError:          false,
		},
		{
			name:                   "Nil policy data",
			containerPolicyEnabled: true,
			updateFunction:         mockUpdateContainerPolicySuccess,
			policyData:             nil,
			invalidJSON:            true,
			expectedStatus:         pb.PolicyStatus_Invalid,
			expectedError:          false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			server := &PolicyServer{
				UpdateContainerPolicy:  tc.updateFunction,
				ContainerPolicyEnabled: tc.containerPolicyEnabled,
			}

			ctx := context.Background()
			req := &pb.Policy{
				Policy: tc.policyData,
			}

			resp, err := server.ContainerPolicy(ctx, req)

			// Check error expectation
			if tc.expectedError && err == nil {
				t.Errorf("Expected error but got none")
			}
			if !tc.expectedError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			// Check response
			if resp == nil {
				t.Fatalf("Response is nil")
			}

			if resp.Status != tc.expectedStatus {
				t.Errorf("Expected status %v, got %v", tc.expectedStatus, resp.Status)
			}
		})
	}
}

func TestPolicyServer_HostPolicy(t *testing.T) {
	testCases := []struct {
		name              string
		hostPolicyEnabled bool
		updateFunction    func(tp.K8sKubeArmorHostPolicyEvent) pb.PolicyStatus
		policyData        []byte
		invalidJSON       bool
		expectedStatus    pb.PolicyStatus
		expectedError     bool
	}{
		{
			name:              "Host policy disabled",
			hostPolicyEnabled: false,
			updateFunction:    mockUpdateHostPolicySuccess,
			policyData:        createValidHostPolicyData(),
			expectedStatus:    pb.PolicyStatus_NotEnabled,
			expectedError:     false,
		},
		{
			name:              "Valid host policy - success",
			hostPolicyEnabled: true,
			updateFunction:    mockUpdateHostPolicySuccess,
			policyData:        createValidHostPolicyData(),
			expectedStatus:    pb.PolicyStatus_Applied,
			expectedError:     false,
		},
		{
			name:              "Valid host policy - failure",
			hostPolicyEnabled: true,
			updateFunction:    mockUpdateHostPolicyFailure,
			policyData:        createValidHostPolicyData(),
			expectedStatus:    pb.PolicyStatus_Invalid,
			expectedError:     false,
		},
		{
			name:              "Empty host policy name",
			hostPolicyEnabled: true,
			updateFunction:    mockUpdateHostPolicySuccess,
			policyData:        createEmptyHostPolicyData(),
			expectedStatus:    pb.PolicyStatus_Invalid,
			expectedError:     false,
		},
		{
			name:              "Invalid JSON data",
			hostPolicyEnabled: true,
			updateFunction:    mockUpdateHostPolicySuccess,
			policyData:        []byte("invalid json"),
			invalidJSON:       true,
			expectedStatus:    pb.PolicyStatus_Invalid,
			expectedError:     false,
		},
		{
			name:              "Nil policy data",
			hostPolicyEnabled: true,
			updateFunction:    mockUpdateHostPolicySuccess,
			policyData:        nil,
			invalidJSON:       true,
			expectedStatus:    pb.PolicyStatus_Invalid,
			expectedError:     false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			server := &PolicyServer{
				UpdateHostPolicy:  tc.updateFunction,
				HostPolicyEnabled: tc.hostPolicyEnabled,
			}

			ctx := context.Background()
			req := &pb.Policy{
				Policy: tc.policyData,
			}

			resp, err := server.HostPolicy(ctx, req)

			// Check error expectation
			if tc.expectedError && err == nil {
				t.Errorf("Expected error but got none")
			}
			if !tc.expectedError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			// Check response
			if resp == nil {
				t.Fatalf("Response is nil")
			}

			if resp.Status != tc.expectedStatus {
				t.Errorf("Expected status %v, got %v", tc.expectedStatus, resp.Status)
			}
		})
	}
}

func TestPolicyServer_PolicyEnabledFlags(t *testing.T) {
	flagTestCases := []struct {
		name                   string
		containerPolicyEnabled bool
		hostPolicyEnabled      bool
	}{
		{"Both policies enabled", true, true},
		{"Only container policy enabled", true, false},
		{"Only host policy enabled", false, true},
		{"Both policies disabled", false, false},
	}

	for _, tc := range flagTestCases {
		t.Run(tc.name, func(t *testing.T) {
			server := &PolicyServer{
				ContainerPolicyEnabled: tc.containerPolicyEnabled,
				HostPolicyEnabled:      tc.hostPolicyEnabled,
			}

			if server.ContainerPolicyEnabled != tc.containerPolicyEnabled {
				t.Errorf("Expected ContainerPolicyEnabled %v, got %v",
					tc.containerPolicyEnabled, server.ContainerPolicyEnabled)
			}

			if server.HostPolicyEnabled != tc.hostPolicyEnabled {
				t.Errorf("Expected HostPolicyEnabled %v, got %v",
					tc.hostPolicyEnabled, server.HostPolicyEnabled)
			}
		})
	}
}

func TestPolicyServer_UpdateFunctions(t *testing.T) {
	updateFunctionTests := []struct {
		name                    string
		containerFunc           func(tp.K8sKubeArmorPolicyEvent) pb.PolicyStatus
		hostFunc                func(tp.K8sKubeArmorHostPolicyEvent) pb.PolicyStatus
		expectedContainerStatus pb.PolicyStatus
		expectedHostStatus      pb.PolicyStatus
	}{
		{
			name:                    "Success functions",
			containerFunc:           mockUpdateContainerPolicySuccess,
			hostFunc:                mockUpdateHostPolicySuccess,
			expectedContainerStatus: pb.PolicyStatus_Applied,
			expectedHostStatus:      pb.PolicyStatus_Applied,
		},
		{
			name:                    "Failure functions",
			containerFunc:           mockUpdateContainerPolicyFailure,
			hostFunc:                mockUpdateHostPolicyFailure,
			expectedContainerStatus: pb.PolicyStatus_Invalid,
			expectedHostStatus:      pb.PolicyStatus_Invalid,
		},
	}

	for _, tc := range updateFunctionTests {
		t.Run(tc.name, func(t *testing.T) {
			server := &PolicyServer{
				UpdateContainerPolicy:  tc.containerFunc,
				UpdateHostPolicy:       tc.hostFunc,
				ContainerPolicyEnabled: true,
				HostPolicyEnabled:      true,
			}

			// Test container policy function
			containerEvent := tp.K8sKubeArmorPolicyEvent{
				Object: tp.K8sKubeArmorPolicy{
					Metadata: metav1.ObjectMeta{Name: "test"},
				},
			}
			containerStatus := server.UpdateContainerPolicy(containerEvent)
			if containerStatus != tc.expectedContainerStatus {
				t.Errorf("Expected container status %v, got %v",
					tc.expectedContainerStatus, containerStatus)
			}

			// Test host policy function
			hostEvent := tp.K8sKubeArmorHostPolicyEvent{
				Object: tp.K8sKubeArmorHostPolicy{
					Metadata: metav1.ObjectMeta{Name: "test"},
				},
			}
			hostStatus := server.UpdateHostPolicy(hostEvent)
			if hostStatus != tc.expectedHostStatus {
				t.Errorf("Expected host status %v, got %v",
					tc.expectedHostStatus, hostStatus)
			}
		})
	}
}

func TestPolicyServer_ContextHandling(t *testing.T) {
	contextTests := []struct {
		name string
		ctx  context.Context
	}{
		{"Background context", context.Background()},
		{"TODO context", context.TODO()},
		{"Context with value", context.WithValue(context.Background(), "key", "value")},
	}

	server := &PolicyServer{
		UpdateContainerPolicy:  mockUpdateContainerPolicySuccess,
		UpdateHostPolicy:       mockUpdateHostPolicySuccess,
		ContainerPolicyEnabled: true,
		HostPolicyEnabled:      true,
	}

	for _, tc := range contextTests {
		t.Run(tc.name+" - ContainerPolicy", func(t *testing.T) {
			req := &pb.Policy{Policy: createValidContainerPolicyData()}
			resp, err := server.ContainerPolicy(tc.ctx, req)

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if resp == nil {
				t.Fatal("Response is nil")
			}
			if resp.Status != pb.PolicyStatus_Applied {
				t.Errorf("Expected status Applied, got %v", resp.Status)
			}
		})

		t.Run(tc.name+" - HostPolicy", func(t *testing.T) {
			req := &pb.Policy{Policy: createValidHostPolicyData()}
			resp, err := server.HostPolicy(tc.ctx, req)

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if resp == nil {
				t.Fatal("Response is nil")
			}
			if resp.Status != pb.PolicyStatus_Applied {
				t.Errorf("Expected status Applied, got %v", resp.Status)
			}
		})
	}
}

func TestPolicyServer_EdgeCases(t *testing.T) {
	edgeCases := []struct {
		name           string
		setupServer    func() *PolicyServer
		testContainer  bool
		testHost       bool
		expectedStatus pb.PolicyStatus
	}{
		{
			name: "Nil update functions",
			setupServer: func() *PolicyServer {
				return &PolicyServer{
					UpdateContainerPolicy:  nil,
					UpdateHostPolicy:       nil,
					ContainerPolicyEnabled: false,
					HostPolicyEnabled:      false,
				}
			},
			testContainer:  true,
			testHost:       true,
			expectedStatus: pb.PolicyStatus_NotEnabled,
		},
	}

	for _, tc := range edgeCases {
		t.Run(tc.name, func(t *testing.T) {
			server := tc.setupServer()
			ctx := context.Background()

			if tc.testContainer {
				req := &pb.Policy{Policy: createValidContainerPolicyData()}
				resp, err := server.ContainerPolicy(ctx, req)
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if resp.Status != tc.expectedStatus {
					t.Errorf("Expected status %v, got %v", tc.expectedStatus, resp.Status)
				}
			}

			if tc.testHost {
				req := &pb.Policy{Policy: createValidHostPolicyData()}
				resp, err := server.HostPolicy(ctx, req)
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if resp.Status != tc.expectedStatus {
					t.Errorf("Expected status %v, got %v", tc.expectedStatus, resp.Status)
				}
			}
		})
	}
}
