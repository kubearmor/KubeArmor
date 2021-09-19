package kvmAgent

import (
	"context"
	"io"
	"log"
	"os"

	pb "github.com/kubearmor/KubeArmor/protobuf"
	"google.golang.org/grpc"
)

// Variables
var (
	client         pb.KVMClient
	grpcClientConn *grpc.ClientConn
)

func getGrpcConnAddress() string {
	return (os.Getenv("gRPC_IP") + ":" + os.Getenv("gRPC_PORT"))
}

func enforcePolicy(policyBytes []byte) error {
	err := *new(error)
	err = nil

	// Print policy details
	log.Printf("Policy data bytes : %s", string(policyBytes))

	return err
}

func connectToKVMService() error {
	err := *new(error)
	var status int32
	err = nil
	status = 0

	stream, err := client.SendPolicy(context.Background())
	if err != nil {
		log.Print("Failed to stream", err)
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

func InitKvmAgent() error {

	// Set error variable
	err := *new(error)
	err = nil

	// Listen on tcp connection to the sepcified IP and PORT
	connAddress := getGrpcConnAddress()

	// Connect to gRPC server
	grpcClientConn, err := grpc.Dial(connAddress, grpc.WithInsecure())
	if err != nil {
		log.Print("Failed to connect to server")
		return err
	}

	identity := pb.AgentIdentity{
		Identity: os.Getenv("USER"),
	}

	client = pb.NewKVMClient(grpcClientConn)
	response, err := client.RegisterAgentIdentity(context.Background(), &identity)
	if err != nil {
		log.Printf("Failed to register identity %d", response.Status)
		return err
	}

	err = connectToKVMService()

	return err
}
