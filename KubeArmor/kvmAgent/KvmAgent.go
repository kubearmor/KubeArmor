package core

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"

	pb "github.com/kubearmor/KubeArmor/protobuf"
	"google.golang.org/grpc"
)

// Variables
var client pb.KVMClient

func getGrpcConnAddress() string {
	return (os.Getenv("gRPC_IP") + ":" + os.Getenv("gRPC_PORT"))
}

func enforcePolicy(policyBytes []byte, policyName string) error {
	err := *new(error)
	err = nil

	// Print policy details
	log.Printf("Policy name is : %s", policyName)
	log.Printf("Policy data bytes : %s", string(policyBytes))

	return err
}

func connectToKVMService() error {
	err := *new(error)
	err = nil

	stream, err := client.SendPolicy(context.Background())
	if err != nil {
		log.Fatal("Failed to stream")
	}

	for {
		policy, err := stream.Recv()
		if err == io.EOF {
			continue
		}
		if err != nil {
			return err
		}
		err = enforcePolicy(policy.PolicyData, policy.PolicyName)
		if err != nil {
			log.Print("Policy Enforcement failed")
		}
		stream.Send(&pb.Status{Status: 100, ErrorMessage: "nil"})
	}

	return err
}

func InitKvmAgent() error {

	// Set error variable
	err := *new(error)
	err = nil

	// Listen on tcp connection to the sepcified IP and PORT
	connAddress := getGrpcConnAddress()
	fmt.Println(connAddress)

	// Connect to gRPC server
	grpcClientConn, err := grpc.Dial(connAddress, grpc.WithInsecure())
	if err != nil {
		log.Fatal("Failed to connect to server")
		return err
	}
	defer grpcClientConn.Close()

	identity := pb.AgentIdentity{
		Identity: os.Getenv("USER"),
	}

	client = pb.NewKVMClient(grpcClientConn)
	response, err := client.RegisterAgentIdentity(context.Background(), &identity)
	if err != nil {
		log.Println("Failed to register identity", err, response.Status, response.ErrorMessage)
		return err
	}

	connectToKVMService()

	return err
}
