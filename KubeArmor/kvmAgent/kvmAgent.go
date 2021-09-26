package kvmAgent

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"os"

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
	return (os.Getenv("gRPC_IP") + ":" + os.Getenv("gRPC_PORT"))
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

	stream, err := client.SendPolicy(ctx)
	if err != nil {
		log.Print("Failed to stream")
		grpcClientConn.Close()
		return err
	}

	for {
		policy, err := stream.Recv()
		if err == io.EOF {
			continue
		}
		if err != nil {
			log.Printf("Error %s ", err)
			break
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

	// Update callback fp
	UpdateHostPolicy = eventCb

	// Listen on tcp connection to the sepcified IP and PORT
	connAddress := getGrpcConnAddress()

	// Connect to gRPC server
	grpcClientConn, err := grpc.Dial(connAddress, grpc.WithInsecure())
	if err != nil {
		log.Print("Failed to connect to server")
		return err
	}

	identity = os.Getenv("IDENTITY")

	client = pb.NewKVMClient(grpcClientConn)

	//response, err := client.RegisterAgentIdentity(context.Background(), &identity)
	response, err := client.RegisterAgentIdentity(context.Background(), &pb.AgentIdentity{Identity: identity})
	if err != nil {
		log.Printf("Failed to register identity %d", response.Status)
		return err
	}

	go connectToKVMService()

	return err
}
