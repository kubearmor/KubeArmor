// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

// Command systemd-tls-check verifies both systemd gRPC endpoints with mTLS.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	pb "github.com/kubearmor/KubeArmor/protobuf"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

type identity struct {
	roots       *x509.CertPool
	certificate tls.Certificate
}

type endpoint struct {
	name     string
	address  string
	identity identity
	probe    func(context.Context, grpc.ClientConnInterface) error
}

func loadIdentity(directory string) (identity, error) {
	caPEM, err := os.ReadFile(filepath.Join(directory, "ca.crt"))
	if err != nil {
		return identity{}, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return identity{}, fmt.Errorf("no CA certificates in %s", directory)
	}
	certificate, err := tls.LoadX509KeyPair(filepath.Join(directory, "client.crt"), filepath.Join(directory, "client.key"))
	if err != nil {
		return identity{}, err
	}
	return identity{roots: roots, certificate: certificate}, nil
}

func checkLog(ctx context.Context, connection grpc.ClientConnInterface) error {
	const nonce = 42
	response, err := pb.NewLogServiceClient(connection).HealthCheck(ctx, &pb.NonceMessage{Nonce: nonce})
	if err != nil {
		return err
	}
	if response.GetRetval() != nonce {
		return fmt.Errorf("log health returned nonce %d, want %d", response.GetRetval(), nonce)
	}
	return nil
}

func checkManagement(ctx context.Context, connection grpc.ClientConnInterface) error {
	_, err := pb.NewProbeServiceClient(connection).GetProbeData(ctx, &emptypb.Empty{})
	return err
}

func (server endpoint) call(ctx context.Context, certificate *tls.Certificate) error {
	config := &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    server.identity.roots,
		ServerName: "localhost",
	}
	if certificate != nil {
		// Force presentation, including for the wrong-CA test. Otherwise Go can
		// omit a certificate whose issuer is not in the server's accepted CAs.
		config.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return certificate, nil
		}
	}
	connection, err := grpc.NewClient(server.address, grpc.WithTransportCredentials(credentials.NewTLS(config)))
	if err != nil {
		return err
	}
	defer connection.Close()

	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return server.probe(ctx, connection)
}

func (server endpoint) waitReady(ctx context.Context) error {
	for {
		err := server.call(ctx, &server.identity.certificate)
		if err == nil {
			fmt.Printf("%s (%s): authenticated RPC ready\n", server.name, server.address)
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("%s did not become ready: %w (last RPC: %v)", server.name, ctx.Err(), err)
		case <-time.After(time.Second):
		}
	}
}

func checkEndpoints(ctx context.Context, servers [2]endpoint) error {
	readyCtx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	for _, server := range servers {
		if err := server.waitReady(readyCtx); err != nil {
			return err
		}
	}

	for i, server := range servers {
		cases := []struct {
			name        string
			certificate *tls.Certificate
		}{
			{"no client certificate", nil},
			{"client certificate from the other endpoint CA", &servers[1-i].identity.certificate},
		}
		for _, test := range cases {
			err := server.call(ctx, test.certificate)
			if err == nil {
				return fmt.Errorf("%s accepted %s", server.name, test.name)
			}
			if status.Code(err) != codes.Unavailable {
				return fmt.Errorf("%s: unexpected failure for %s: %w", server.name, test.name, err)
			}
			fmt.Printf("%s: rejected %s\n", server.name, test.name)
		}
	}

	// Recheck both endpoints so a stopped daemon cannot pass the rejection tests.
	for _, server := range servers {
		if err := server.call(ctx, &server.identity.certificate); err != nil {
			return fmt.Errorf("%s: authenticated RPC failed after rejection tests: %w", server.name, err)
		}
	}
	return nil
}

func run() error {
	logDirectory := flag.String("log-cert-dir", "", "directory containing log ca.crt, client.crt and client.key")
	managementDirectory := flag.String("management-cert-dir", "", "directory containing management ca.crt, client.crt and client.key")
	flag.Parse()
	if *logDirectory == "" || *managementDirectory == "" {
		return fmt.Errorf("both -log-cert-dir and -management-cert-dir are required")
	}
	logIdentity, err := loadIdentity(*logDirectory)
	if err != nil {
		return fmt.Errorf("load log credentials: %w", err)
	}
	managementIdentity, err := loadIdentity(*managementDirectory)
	if err != nil {
		return fmt.Errorf("load management credentials: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	return checkEndpoints(ctx, [2]endpoint{
		{name: "log", address: "localhost:32767", identity: logIdentity, probe: checkLog},
		{name: "management", address: "localhost:32765", identity: managementIdentity, probe: checkManagement},
	})
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "systemd mTLS check failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Systemd mTLS checks passed for log and management endpoints")
}
