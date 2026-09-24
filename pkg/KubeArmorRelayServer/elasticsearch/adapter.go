// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package elasticsearch

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/dustin/go-humanize"
	"github.com/elastic/go-elasticsearch/v7"
	"github.com/elastic/go-elasticsearch/v7/esutil"
	"github.com/google/uuid"
	kg "github.com/kubearmor/KubeArmor/pkg/KubeArmorRelayServer/log"
	pb "github.com/kubearmor/KubeArmor/protobuf"
)

var (
	countSuccessful uint64
	countEntered    uint64
	start           time.Time
)

// ElasticsearchClient Structure
type ElasticsearchClient struct {
	esClient    *elasticsearch.Client
	cancel      context.CancelFunc
	bulkIndexer esutil.BulkIndexer
	ctx         context.Context
	alertCh     chan interface{}
}

// NewElasticsearchClient creates a new Elasticsearch client with the given Elasticsearch URL
// and kubearmor LogClient with endpoint. It has a retry mechanism for certain HTTP status codes and a backoff function for retry delays.
// It then creates a new NewBulkIndexer with the esClient
func NewElasticsearchClient(esURL string, esUser string, esPassword string, esCaCertPath string, esAllowInsecureTLS bool) (*ElasticsearchClient, error) {

	retryBackoff := backoff.NewExponentialBackOff()
	cfg := elasticsearch.Config{
		Addresses: []string{esURL},

		// Retry on 429 TooManyRequests statuses
		RetryOnStatus: []int{502, 503, 504, 429},

		// Configure the backoff function
		RetryBackoff: func(i int) time.Duration {
			if i == 1 {
				retryBackoff.Reset()
			}
			return retryBackoff.NextBackOff()
		},
		MaxRetries: 5,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: esAllowInsecureTLS,
			},
		},
	}

	if esCaCertPath != "" {
		caCertBytes, err := os.ReadFile(esCaCertPath)
		if err != nil {
			return nil, fmt.Errorf("failed to open Elasticsearch CA file: %v", err)
		}
		cfg.CACert = caCertBytes
	}

	if len(esUser) != 0 && len(esPassword) != 0 {
		cfg.Username = esUser
		cfg.Password = esPassword
	}

	esClient, err := elasticsearch.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create Elasticsearch client: %v", err)
	}
	bi, err := esutil.NewBulkIndexer(esutil.BulkIndexerConfig{
		Client:        esClient,         // The Elasticsearch client
		FlushBytes:    1000000,          // The flush threshold in bytes [1mb]
		FlushInterval: 10 * time.Second, // The periodic flush interval [30 secs]
		OnError: func(ctx context.Context, err error) {
			log.Fatalf("Error creating the indexer: %v", err)
		},
	})
	if err != nil {
		log.Fatalf("Error creating the indexer: %v", err)
	}
	alertCh := make(chan interface{}, 10000)
	return &ElasticsearchClient{bulkIndexer: bi, esClient: esClient, alertCh: alertCh}, nil
}

// bulkIndex takes an interface and index name and adds the data to the Elasticsearch bulk indexer.
// The bulk indexer flushes after the FlushBytes or FlushInterval thresholds are reached.
// The method generates a UUID as the document ID and includes success and failure callbacks for each item added to the bulk indexer.
func (ecl *ElasticsearchClient) bulkIndex(a interface{}, index string) {
	countEntered++
	data, err := json.Marshal(a)
	if err != nil {
		log.Fatalf("Error marshaling data: %s", err)
	}

	err = ecl.bulkIndexer.Add(
		ecl.ctx,
		esutil.BulkIndexerItem{
			Index:      index,
			Action:     "index",
			DocumentID: uuid.New().String(),
			Body:       bytes.NewReader(data),
			OnSuccess: func(ctx context.Context, item esutil.BulkIndexerItem, res esutil.BulkIndexerResponseItem) {
				atomic.AddUint64(&countSuccessful, 1)
			},
			OnFailure: func(ctx context.Context, item esutil.BulkIndexerItem, res esutil.BulkIndexerResponseItem, err error) {
				if err != nil {
					log.Printf("ERROR: %s", err)
				} else {
					log.Printf("ERROR: %s: %s", res.Error.Type, res.Error.Reason)
				}
			},
		},
	)

	if err != nil {
		log.Fatalf("Error adding items to bulk indexer: %s", err)
	}
}

func (ecl *ElasticsearchClient) SendAlertToBuffer(alert *pb.Alert) {
	ecl.alertCh <- alert
}

// Start starts the Elasticsearch client by performing a health check on the gRPC server
// and starting goroutines to consume messages from the alert channel and bulk index them.
// The method starts a goroutine for each stream and waits for messages to be received.
// Additional goroutines consume alert from the alert channel and bulk index them.
func (ecl *ElasticsearchClient) Start(AlertsIndex string) error {
	start = time.Now()
	ecl.ctx, ecl.cancel = context.WithCancel(context.Background())
	var wg sync.WaitGroup

	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			for {
				select {
				case alert := <-ecl.alertCh:
					ecl.bulkIndex(alert, AlertsIndex)
				case <-ecl.ctx.Done():
					return
				}
			}
		}()
	}
	wg.Wait()
	return nil
}

// Stop stops the Elasticsearch client and performs necessary cleanup operations.
// It stops the Kubearmor Relay client, closes the BulkIndexer and cancels the context.
func (ecl *ElasticsearchClient) Stop() error {

	//Close BulkIndexer
	if err := ecl.bulkIndexer.Close(ecl.ctx); err != nil {
		kg.Errf("Unexpected error: %s", err)
	}

	ecl.cancel()

	kg.Printf("Stopped kubearmor receiver")
	time.Sleep(2 * time.Second)
	ecl.PrintBulkStats()
	return nil
}

// PrintBulkStats prints data on the bulk indexing process, including the number of indexed documents,
// the number of errors, and the indexing rate , after elasticsearch client stops
func (ecl *ElasticsearchClient) PrintBulkStats() {
	biStats := ecl.bulkIndexer.Stats()
	println(strings.Repeat("▔", 80))

	dur := time.Since(start)

	if biStats.NumFailed > 0 {
		fmt.Printf(
			"Indexed [%s] documents with [%s] errors in %s (%s docs/sec)",
			humanize.Commaf(float64(biStats.NumFlushed)),
			humanize.Commaf(float64(biStats.NumFailed)),
			dur.Truncate(time.Millisecond),
			humanize.Commaf(float64(1000.0/float64(dur/time.Millisecond)*float64(biStats.NumFlushed))),
		)
	} else {
		log.Printf(
			"Successfuly indexed [%s] documents in %s (%s docs/sec)",
			humanize.Commaf(float64(biStats.NumFlushed)),
			dur.Truncate(time.Millisecond),
			humanize.Commaf(float64(1000.0/float64(dur/time.Millisecond)*float64(biStats.NumFlushed))),
		)
	}
	println(strings.Repeat("▔", 80))
}
