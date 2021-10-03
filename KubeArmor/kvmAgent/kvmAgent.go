package kvmAgent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
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

func getGrpcConnAddress() string {
	return (os.Getenv("CLUSTER_IP") + ":" + os.Getenv("CLUSTER_PORT"))
}

func enforcePolicy(policyBytes []byte) error {
	err := *new(error)
	err = nil
	policyEvent := tp.K8sKubeArmorHostPolicyEvent{}

	err = json.Unmarshal(policyBytes, &policyEvent)
	if err != nil {
		log.Print("Unmarshal error => ", err)
	} else {
		UpdateHostPolicy(policyEvent)
	}

	return err
}

func connectToKVMService() error {
	err := *new(error)
	var status int32
	err = nil
	status = 0

	md := metadata.New(map[string]string{"identity": identity})
	ctx := metadata.NewOutgoingContext(context.Background(), md)

	kg.Print("Connecting stream to server")

	stream, err := client.SendPolicy(ctx)
	if err != nil {
		kg.Print("Failed to stream")
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
			log.Print("Policy Enforcement failed")
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

	// Set error variable
	err := *new(error)
	err = nil

	// Update callback FP
	UpdateHostPolicy = eventCb
	connAddress := getGrpcConnAddress()
	identity = os.Getenv("WORKLOAD_IDENTITY")

	// Connect to gRPC server
	ctx, _ := context.WithTimeout(context.Background(), 30*time.Second)
	grpcClientConn, err := grpc.DialContext(ctx, connAddress, grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		kg.Printf("gRPC Dial failed")
		return err
	}

	client = pb.NewKVMClient(grpcClientConn)
	if client == nil {
		return errors.New("Invalid Client handle")
	}

	response, err := client.RegisterAgentIdentity(context.Background(), &pb.AgentIdentity{Identity: identity})
	if err != nil || response.Status != 0 {
		return errors.New("Failed to register client Identity")
	}

	go connectToKVMService()

	return err
}
