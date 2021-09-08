package core

import (
	"context"
	"fmt"
	"log"
	"os"

	pb "github.com/kubearmor/KubeArmor/protobuf"
	"google.golang.org/grpc"
)

var client pb.KVMClient

func getGrpcConnAddress() string {
	return (os.Getenv("gRPC_IP") + ":" + os.Getenv("gRPC_PORT"))
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
		log.Println("Failed to register identity", err)
		return err
	} else {
		fmt.Println("Response is ", response.Status, response.ErrorMessage)
	}

	return err
}
