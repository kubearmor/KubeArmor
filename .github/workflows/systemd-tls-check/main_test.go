// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	pb "github.com/kubearmor/KubeArmor/protobuf"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/types/known/emptypb"
)

func testIdentity(t *testing.T) identity {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(2), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		DNSNames: []string{"localhost"}, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return identity{roots: roots, certificate: tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: key}}
}

type testLogService struct {
	pb.UnimplementedLogServiceServer
	wrongNonce bool
}

func (server testLogService) HealthCheck(_ context.Context, request *pb.NonceMessage) (*pb.ReplyMessage, error) {
	nonce := request.Nonce
	if server.wrongNonce {
		nonce++
	}
	return &pb.ReplyMessage{Retval: nonce}, nil
}

type testProbeService struct {
	pb.UnimplementedProbeServiceServer
}

func (testProbeService) GetProbeData(context.Context, *emptypb.Empty) (*pb.ProbeResponse, error) {
	return &pb.ProbeResponse{}, nil
}

func testEndpoint(t *testing.T, name string, clientAuth tls.ClientAuthType, wrongNonce bool) endpoint {
	t.Helper()
	id := testIdentity(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{id.certificate},
		ClientCAs: id.roots, ClientAuth: clientAuth,
	})))
	probe := checkLog
	if name == "log" {
		pb.RegisterLogServiceServer(server, testLogService{wrongNonce: wrongNonce})
	} else {
		pb.RegisterProbeServiceServer(server, testProbeService{})
		probe = checkManagement
	}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	return endpoint{name: name, address: listener.Addr().String(), identity: id, probe: probe}
}

func TestCheckEndpoints(t *testing.T) {
	servers := [2]endpoint{
		testEndpoint(t, "log", tls.RequireAndVerifyClientCert, false),
		testEndpoint(t, "management", tls.RequireAndVerifyClientCert, false),
	}
	if err := checkEndpoints(context.Background(), servers); err != nil {
		t.Fatal(err)
	}
}

func TestCheckEndpointsDetectsMissingClientVerification(t *testing.T) {
	for _, test := range []struct {
		name       string
		clientAuth tls.ClientAuthType
		wantError  string
	}{
		{"client certificate optional", tls.NoClientCert, "accepted no client certificate"},
		{"client CA unchecked", tls.RequireAnyClientCert, "accepted client certificate from the other endpoint CA"},
	} {
		t.Run(test.name, func(t *testing.T) {
			servers := [2]endpoint{
				testEndpoint(t, "log", test.clientAuth, false),
				testEndpoint(t, "management", tls.RequireAndVerifyClientCert, false),
			}
			err := checkEndpoints(context.Background(), servers)
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("checkEndpoints = %v, want %q", err, test.wantError)
			}
		})
	}
}

func TestReadinessRequiresSuccessfulRPC(t *testing.T) {
	server := testEndpoint(t, "log", tls.RequireAndVerifyClientCert, true)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	err := server.waitReady(ctx)
	if err == nil || !strings.Contains(err.Error(), "returned nonce 43, want 42") {
		t.Fatalf("waitReady = %v, want failed nonce check", err)
	}
}
