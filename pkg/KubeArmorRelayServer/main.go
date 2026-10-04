// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package main

import (
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kubearmor/KubeArmor/pkg/KubeArmorRelayServer/elasticsearch"
	"github.com/kubearmor/KubeArmor/pkg/KubeArmorRelayServer/opensearch"

	cfg "github.com/kubearmor/KubeArmor/pkg/KubeArmorRelayServer/config"
	kg "github.com/kubearmor/KubeArmor/pkg/KubeArmorRelayServer/log"
	"github.com/kubearmor/KubeArmor/pkg/KubeArmorRelayServer/server"
)

// StopChan Channel
var StopChan chan struct{}

// init Function
func init() {
	StopChan = make(chan struct{})
}

// ==================== //
// == Signal Handler == //
// ==================== //

// GetOSSigChannel Function
func GetOSSigChannel() chan os.Signal {
	c := make(chan os.Signal, 1)

	signal.Notify(c,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT,
		os.Interrupt)

	return c
}

// ========== //
// == Main == //
// ========== //

func main() {
	// == //

	// get arguments
	if err := cfg.LoadConfig(); err != nil {
		kg.Err(err.Error())
		return
	}

	//get env
	enableEsDashboards := os.Getenv("ENABLE_DASHBOARDS")
	enableOsDashboards := os.Getenv("ENABLE_OPENSEARCH_DASHBOARD")
	esUrl := os.Getenv("ES_URL")
	esUser := os.Getenv("ES_USERNAME")
	esPassword := os.Getenv("ES_PASSWORD")
	esCaCertPath := os.Getenv("ES_CA_CERT_PATH")
	esAllowInsecureTLS := false
	if os.Getenv("ES_ALLOW_INSECURE_TLS") != "" {
		esAllowInsecureTLS = true
	}
	esAlertsIndex := os.Getenv("ES_ALERTS_INDEX")
	if esAlertsIndex == "" {
		esAlertsIndex = "kubearmor-alerts"
	}
	endPoint := os.Getenv("KUBEARMOR_SERVICE")
	if endPoint == "" {
		endPoint = "localhost:32767"
	}

	// == //

	// create a relay server
	relayServer := server.NewRelayServer(cfg.GlobalConfig.GRPC)
	if relayServer == nil {
		kg.Warnf("Failed to create a relay server (:%s)", cfg.GlobalConfig.GRPC)
		return
	}
	kg.Printf("Created a relay server (:%s)", cfg.GlobalConfig.GRPC)

	// serve log feeds (to clients)
	go relayServer.ServeLogFeeds()
	kg.Print("Started to serve gRPC-based log feeds")

	// get log feeds (from KubeArmor)
	go relayServer.GetFeedsFromNodes()
	kg.Print("Started to receive log feeds from each node")

	// == //

	// check and start an elasticsearch client
	if enableEsDashboards == "true" {
		esCl, err := elasticsearch.NewElasticsearchClient(esUrl, esUser, esPassword, esCaCertPath, esAllowInsecureTLS)
		if err != nil {
			kg.Warnf("Failed to start a Elasticsearch Client, %v", err)
			return
		}
		relayServer.ELKClient = esCl
		go relayServer.ELKClient.Start(esAlertsIndex)
		defer relayServer.ELKClient.Stop()
	}

	if enableOsDashboards == "true" {
		batchsize := 10
		flushtime := 10 * time.Second
		osClient, err := opensearch.NewOpenSearchClient(batchsize, flushtime)
		if err != nil {
			kg.Errf("Failed to start a OpenSearchClient Client, %v", err)
			return
		}
		relayServer.OSClient = osClient

		defer relayServer.OSClient.Stop()
	}

	// == //

	// listen for interrupt signals
	sigChan := GetOSSigChannel()
	<-sigChan
	close(StopChan)

	// destroy the relay server
	if err := relayServer.DestroyRelayServer(); err != nil {
		kg.Warnf("Failed to destroy the relay server (%s)", err.Error())
		return
	}
	kg.Print("Destroyed the relay server")

	// == //
}
