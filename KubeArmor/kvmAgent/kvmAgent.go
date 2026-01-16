// SPDX-License-Identifier: Apache-2.0
// Copyright 2026  Authors of KubeArmor

// Package kvmagent contains utilities to connect to kvmservice to establish support on bare-metal env
package kvmagent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"strings"

	kg "github.com/kubearmor/KubeArmor/KubeArmor/log"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"

	pb "github.com/kubearmor/KubeArmor/protobuf"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

// const variables
const errIdentityRemoved = "err-identity-removed"

// KVMAgent Structure
type KVMAgent struct {
	Identity         string
	gRPCServer       string
	gRPCConnection   *grpc.ClientConn
	gRPCClient       pb.KVMClient
	UpdateHostPolicy func(tp.K8sKubeArmorHostPolicyEvent) pb.PolicyStatus
}

func getgRPCAddress() (string, error) {
	serverAddr := net.JoinHostPort(os.Getenv("CLUSTER_IP"), os.Getenv("CLUSTER_PORT"))
	if serverAddr == ":" {
		return "", errors.New("either CLUSTER_IP or CLUSTER_PORT is not set")
	}
	return serverAddr, nil
}

// NewKVMAgent Function
func NewKVMAgent(eventCb tp.KubeArmorHostPolicyEventCallback) *KVMAgent {
	kvm := &KVMAgent{}

	// Get identity
	kvm.Identity = os.Getenv("WORKLOAD_IDENTITY")

	// Get the address of gRPC server
	gRPCServer, err := getgRPCAddress()
	if err != nil {
		kg.Errf("Failed to get gRPC address", err.Error())
		return nil
	}

	kvm.gRPCServer = gRPCServer

	// Connect to gRPC server
	gRPCConnection, err := grpc.NewClient(kvm.gRPCServer, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		kg.Errf("Not accessible to gRPC server (%s)", err.Error())
		return nil
	}

	kvm.gRPCConnection = gRPCConnection
	kvm.gRPCClient = pb.NewKVMClient(gRPCConnection)

	// Register identity
	response, err := kvm.gRPCClient.RegisterAgentIdentity(context.Background(), &pb.AgentIdentity{Identity: kvm.Identity})
	if err != nil || response.Status != 0 {
		kg.Errf("Failed to register KVM agent identity (%s)", err.Error())
		return nil
	}

	// Link ParseAndUpdateHostSecurityPolicy()
	kvm.UpdateHostPolicy = eventCb

	return kvm
}

// DestroyKVMAgent Function
func (kvm *KVMAgent) DestroyKVMAgent() error {
	if err := kvm.gRPCConnection.Close(); err != nil {
		return err
	}
	return nil
}

// ConnectToKVMService Function
func (kvm *KVMAgent) ConnectToKVMService() {
	for {
		md := metadata.New(map[string]string{"identity": kvm.Identity})
		ctx := metadata.NewOutgoingContext(context.Background(), md)

		stream, err := kvm.gRPCClient.SendPolicy(ctx)
		if err != nil {
			kg.Warnf("Unable to connect stream (%s)", err.Error())

			// close the connection
			if err = kvm.gRPCConnection.Close(); err != nil {
				kg.Warnf("Unable to close the current connection (%s)", err.Error())
			}

			// connect to gRPC server again
			gRPCConnection, err := grpc.NewClient(kvm.gRPCServer, grpc.WithTransportCredentials(insecure.NewCredentials()))
			if err != nil {
				kg.Errf("Not accessible to gRPC server (%s)", err.Error())
				return
			}

			// update Connection and Client
			kvm.gRPCConnection = gRPCConnection
			kvm.gRPCClient = pb.NewKVMClient(gRPCConnection)

			continue
		}

		for {
			status := int32(0)
			policyEvent := tp.K8sKubeArmorHostPolicyEvent{}

			policy, err := stream.Recv()
			if err == io.EOF {
				continue
			} else if err != nil {

				if strings.Contains(string(err.Error()), errIdentityRemoved) {
					kg.Warn("Identity removed from server")
					// close the connection
					if err = kvm.gRPCConnection.Close(); err != nil {
						kg.Warn("Failed to close the current connection")
					}
					return
				}

				// close the connection
				if err = kvm.gRPCConnection.Close(); err != nil {
					kg.Warnf("Unable to close the current connection (%s)", err.Error())
				}

				// connect to gRPC server again
				gRPCConnection, err := grpc.NewClient(kvm.gRPCServer, grpc.WithTransportCredentials(insecure.NewCredentials()))
				if err != nil {
					kg.Errf("Not accessible to gRPC server (%s)", err.Error())
					return
				}

				// update Connection and Client
				kvm.gRPCConnection = gRPCConnection
				kvm.gRPCClient = pb.NewKVMClient(gRPCConnection)

				break
			}

			// get a policy
			err = json.Unmarshal(policy.PolicyData, &policyEvent)
			if err == nil {
				// update the policy
				kvm.UpdateHostPolicy(policyEvent)
			} else {
				kg.Warnf("Unable to load a policy (%s)", err.Error())
				status = 1
			}

			// return the status
			if err = stream.Send(&pb.Status{Status: status}); err != nil {
				kg.Warnf("Unable to send the status (%s)", err.Error())
			}
		}
	}
}
