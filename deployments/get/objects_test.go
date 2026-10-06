// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package deployments

import (
	"strconv"
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func containerPort(t *testing.T, ports []corev1.ContainerPort, name string) int32 {
	t.Helper()
	for _, p := range ports {
		if p.Name == name {
			return p.ContainerPort
		}
	}
	t.Fatalf("container port %q not found", name)
	return 0
}

func TestGRPCPortGeneration(t *testing.T) {
	tests := []struct {
		name string
		port int32
	}{
		{name: "default port", port: DefaultGRPCPort},
		{name: "custom port outside NodePort range", port: 28080},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svcPort := GetRelayService("kubearmor", tt.port).Spec.Ports[0]
			if svcPort.Port != tt.port || svcPort.TargetPort.IntValue() != int(tt.port) {
				t.Errorf("relay service port/targetPort = %d/%d, want %d", svcPort.Port, svcPort.TargetPort.IntValue(), tt.port)
			}

			relayPorts := GetRelayDeployment("kubearmor", tt.port).Spec.Template.Spec.Containers[0].Ports
			if relayPorts[0].ContainerPort != tt.port {
				t.Errorf("relay containerPort = %d, want %d", relayPorts[0].ContainerPort, tt.port)
			}

			container := GenerateDaemonSet("generic", "kubearmor", tt.port).Spec.Template.Spec.Containers[0]
			if want := "-gRPC=" + strconv.Itoa(int(tt.port)); container.Args[0] != want {
				t.Errorf("sensor arg = %q, want %q", container.Args[0], want)
			}
			if got := containerPort(t, container.Ports, "grpc"); got != tt.port {
				t.Errorf("sensor grpc containerPort = %d, want %d", got, tt.port)
			}

			// the health port is configured independently of the gRPC port
			if got := containerPort(t, container.Ports, "grpc-health"); got != healthPort {
				t.Errorf("sensor grpc-health containerPort = %d, want %d", got, healthPort)
			}
			if got := container.LivenessProbe.GRPC.Port; got != healthPort {
				t.Errorf("sensor liveness probe port = %d, want %d", got, healthPort)
			}
		})
	}
}

// the default port must stay unchanged for existing users
func TestDefaultGRPCPort(t *testing.T) {
	if DefaultGRPCPort != 32767 {
		t.Errorf("DefaultGRPCPort = %d, want 32767", DefaultGRPCPort)
	}
}

// a custom port must not leave the default port behind in any generated resource
func TestCustomGRPCPortHasNoDefaultPort(t *testing.T) {
	const custom int32 = 28080

	svcPort := GetRelayService("kubearmor", custom).Spec.Ports[0]
	if svcPort.Port == DefaultGRPCPort || svcPort.TargetPort.IntValue() == int(DefaultGRPCPort) {
		t.Errorf("relay service still uses the default port: %d/%d", svcPort.Port, svcPort.TargetPort.IntValue())
	}
	if p := GetRelayDeployment("kubearmor", custom).Spec.Template.Spec.Containers[0].Ports[0].ContainerPort; p == DefaultGRPCPort {
		t.Errorf("relay containerPort still uses the default port: %d", p)
	}
	container := GenerateDaemonSet("generic", "kubearmor", custom).Spec.Template.Spec.Containers[0]
	for _, p := range container.Ports {
		if p.ContainerPort == DefaultGRPCPort {
			t.Errorf("sensor container port %q still uses the default port", p.Name)
		}
	}
	for _, arg := range container.Args {
		if arg == "-gRPC="+strconv.Itoa(int(DefaultGRPCPort)) {
			t.Errorf("sensor args still contain the default port: %v", container.Args)
		}
	}
}
