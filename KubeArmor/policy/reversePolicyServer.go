// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of KubeArmor

package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	kg "github.com/kubearmor/KubeArmor/KubeArmor/log"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
	pb "github.com/kubearmor/KubeArmor/protobuf"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"
)

type ReversePolicyServer struct {
	RelayServerURL string
	Running        bool
	Wg             sync.WaitGroup

	Conn   *grpc.ClientConn
	Client pb.ReversePolicyServiceClient

	ContainerPolicyClient pb.ReversePolicyService_ContainerPolicyClient
	HostPolicyClient      pb.ReversePolicyService_HostPolicyClient

	UpdateContainerPolicy func(tp.K8sKubeArmorPolicyEvent) pb.PolicyStatus
	UpdateHostPolicy      func(tp.K8sKubeArmorHostPolicyEvent) pb.PolicyStatus
}

func (p *ReversePolicyServer) ContainerPolicy() {
	defer p.Wg.Done()

	var err error
	for p.Running {
		var event *pb.Policy

		if event, err = p.ContainerPolicyClient.Recv(); err != nil {
			kg.Warnf("Failed to receive a ContainerPolicy %s", err)
			return
		}

		policyEvent := tp.K8sKubeArmorPolicyEvent{}

		res := new(pb.Response)

		err := json.Unmarshal(event.Policy, &policyEvent)
		if err == nil {
			if policyEvent.Object.Metadata.Name != "" {
				res.Status = p.UpdateContainerPolicy(policyEvent)
			} else {
				kg.Warn("Empty Container Policy Event")
				res.Status = pb.PolicyStatus_Invalid
			}
		} else {
			kg.Warnf("Invalid Container Policy: Failed to clone a policy: %s", err)
			res.Status = pb.PolicyStatus_Invalid
		}

		if err = kl.HandleGRPCErrors(p.ContainerPolicyClient.Send(res)); err != nil {
			kg.Warnf("Failed to send a ContainerPolicy status response=[%+v] err=[%s]", res, err.Error())
			continue
		}
	}

	return
}

func (p *ReversePolicyServer) HostPolicy() {
	defer p.Wg.Done()

	var err error
	for p.Running {
		var event *pb.Policy

		if event, err = p.HostPolicyClient.Recv(); err != nil {
			kg.Warnf("Failed to receive a HostPolicy %s", err)
			return
		}

		policyEvent := tp.K8sKubeArmorHostPolicyEvent{}
		res := new(pb.Response)

		err := json.Unmarshal(event.Policy, &policyEvent)
		if err == nil {
			if policyEvent.Object.Metadata.Name != "" {
				res.Status = p.UpdateHostPolicy(policyEvent)
			} else {
				kg.Warn("Empty HostPolicy Event")
				res.Status = pb.PolicyStatus_Invalid
			}
		} else {
			kg.Warnf("Invalid HostPolicy: Failed to clone a policy: %s", err)
			res.Status = pb.PolicyStatus_Invalid
		}

		if err = kl.HandleGRPCErrors(p.HostPolicyClient.Send(res)); err != nil {
			kg.Warnf("Failed to send a HostPolicy status response=[%+v] err=[%s]", res, err.Error())
			continue
		}
	}

	return
}

// TODO: use single gRPC connection for both the clients
func (ps *ReversePolicyServer) connectWithRelay() {
	var (
		err    error
		conn   *grpc.ClientConn
		client pb.ReversePolicyServiceClient
	)

	kacp := keepalive.ClientParameters{
		Time:                1 * time.Second,
		Timeout:             5 * time.Second,
		PermitWithoutStream: true,
	}

	for ps.Running {
		conn, err = grpc.Dial(ps.RelayServerURL, grpc.WithInsecure(), grpc.WithKeepaliveParams(kacp))
		if err != nil {
			kg.Warnf("Failed to connect to relay's gRPC listener. %s", err.Error())
			time.Sleep(time.Second * 5)
			_ = conn.Close()
			continue
		}

		client = pb.NewReversePolicyServiceClient(conn)

		healthClient := grpc_health_v1.NewHealthClient(conn)
		healthCheckRequest := &grpc_health_v1.HealthCheckRequest{
			Service: pb.ReversePolicyService_ServiceDesc.ServiceName,
		}

		resp, err := healthClient.Check(context.Background(), healthCheckRequest)
		grpcErr := kl.HandleGRPCErrors(err)
		if grpcErr != nil {
			kg.Debugf("ReversePolicyServer unhealthy. Error: %s", grpcErr.Error())
			_ = conn.Close()
			time.Sleep(time.Second * 5)
			continue
		}

		switch resp.Status {
		case grpc_health_v1.HealthCheckResponse_SERVING:
			break
		case grpc_health_v1.HealthCheckResponse_NOT_SERVING:
			_ = conn.Close()
			return
		default:
			kg.Debugf("ReversePolicyServer unhealthy. Status: %s", resp.Status.String())
			continue
		}

		break
	}

	ps.Conn = conn
	ps.Client = client

	ps.ContainerPolicyClient, err = ps.Client.ContainerPolicy(context.Background())
	if err != nil {
		kg.Warnf("Failed to start ContainerPolicy stream reader err=%s", err.Error())
		return
	}

	ps.HostPolicyClient, err = ps.Client.HostPolicy(context.Background())
	if err != nil {
		kg.Warnf("Failed to start HostPolicy stream reader err=%s", err.Error())
		return
	}

	return
}

func NewReversePolicyServer(address string) *ReversePolicyServer {
	host, port, err := kl.ParseURL(address)
	if err != nil {
		kg.Errf("Failed to parse Relay Server URL: %s", err.Error())
		return nil
	}

	return &ReversePolicyServer{
		Running:        true,
		RelayServerURL: fmt.Sprintf("%s:%s", host, port),
		Wg:             sync.WaitGroup{},
	}
}

func (ps *ReversePolicyServer) DestroyReversePolicyServer() error {
	ps.Running = false

	if ps.Conn != nil {
		if err := ps.Conn.Close(); err != nil {
			return err
		}
	}

	return nil
}

func (ps *ReversePolicyServer) WatchPolicies() {
	for ps.Running {
		ps.connectWithRelay()
		if ps.Client == nil {
			kg.Errf("Error while connecting with relay for streaming policies")
			return
		}

		kg.Printf("Connected with Relay server for streaming policies")

		if ps.UpdateContainerPolicy != nil {
			ps.Wg.Add(1)
			go ps.ContainerPolicy()
			kg.Printf("Started to stream ContainerPolicy")
		}

		if ps.UpdateHostPolicy != nil {
			ps.Wg.Add(1)
			go ps.HostPolicy()
			kg.Printf("Started to stream HostPolicy")
		}

		ps.Wg.Wait()

		if err := ps.Conn.Close(); err != nil {
			kg.Warnf("Failed to delete PolicyClient: %s", err.Error())
		}
		kg.Printf("Closed PolicyClient for %s", ps.RelayServerURL)

		ps.Client = nil
	}

	return
}
