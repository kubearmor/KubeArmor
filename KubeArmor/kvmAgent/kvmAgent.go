package kvmAgent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"syscall"
	"time"

	kg "github.com/kubearmor/KubeArmor/KubeArmor/log"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
	pb "github.com/kubearmor/KubeArmor/protobuf"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// Variables
var (
	client           pb.KVMClient
	identity         string
	grpcClientConn   grpc.ClientConn
	UpdateHostPolicy func(tp.K8sKubeArmorHostPolicyEvent)
)

func getGrpcConnAddress() (string, error) {
	serverAddr := net.JoinHostPort(os.Getenv("CLUSTER_IP"), os.Getenv("CLUSTER_PORT"))
	if serverAddr == ":" {
		return "", errors.New("host and port value is empty")
	} else {
		return serverAddr, nil
	}
}

func enforcePolicy(policyBytes []byte) error {
	policyEvent := tp.K8sKubeArmorHostPolicyEvent{}

	err := json.Unmarshal(policyBytes, &policyEvent)
	if err == nil {
		UpdateHostPolicy(policyEvent)
	}
	return err
}

func connectToKVMService(identity string) error {
	var status int32
	status = 0

	md := metadata.New(map[string]string{"identity": identity})
	ctx := metadata.NewOutgoingContext(context.Background(), md)

	kg.Print("Connecting client stream to server")

	stream, err := client.SendPolicy(ctx)
	if err != nil {
		kg.Err("Failed to connect stream")
		grpcClientConn.Close()
		return err
	}

	for {
		policy, err := stream.Recv()
		if err == io.EOF {
			continue
		}
		if err != nil {
			syscall.Kill(syscall.Getpid(), syscall.SIGINT)
			return err
		}
		err = enforcePolicy(policy.PolicyData)
		if err != nil {
			kg.Print("Policy Enforcement failed")
			status = 1
		} else {
			status = 0
		}
		stream.Send(&pb.Status{Status: status})
	}

	grpcClientConn.Close()

	return err
}

func InitKvmAgent(eventCb tp.KubeArmorHostPolicyEventCallback) error {

	// Update callback FP
	UpdateHostPolicy = eventCb
	connAddress, err := getGrpcConnAddress()
	if err != nil {
		return err
	}

	identity := os.Getenv("WORKLOAD_IDENTITY")

	// Connect to gRPC server
	ctx, _ := context.WithTimeout(context.Background(), 30*time.Second)
	grpcClientConn, err := grpc.DialContext(ctx, connAddress, grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		kg.Err("gRPC Dial failed")
		return err
	}
	//defer grpcClientConn.Close()

	client = pb.NewKVMClient(grpcClientConn)
	if client == nil {
		return errors.New("invalid client handle")
	}

	response, err := client.RegisterAgentIdentity(context.Background(), &pb.AgentIdentity{Identity: identity})
	if err != nil || response.Status != 0 {
		return errors.New("failed to register client identity")
	}

	go connectToKVMService(identity)

	return err
}
