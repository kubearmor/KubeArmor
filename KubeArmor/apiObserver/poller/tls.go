// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package poller

import (
	"errors"
	"fmt"
	"log"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"

	"github.com/kubearmor/KubeArmor/KubeArmor/apiObserver/events"
)

// TlsPoller drains the ks_chunks_buffer perf event array and reconstructs
// TCP streams from TLS plaintext chunks. It mirrors Kubeshark Tracer's
// pkg/bpf/tls_poller.go, adapted to deliver TlsChunkEvents instead of
// gopacket.Packet (the dissector layer handles packet construction).
//
// Each ks_tls_chunk encodes a slice of plaintext data with:
//   - address info (src/dst IP + port, resolved by tcp_kprobes)
//   - client/server role (from connect/accept tracepoints)
//   - FD and PID (for stream key construction)
//
// Chunks from the same SSL operation are emitted sequentially and share
// the same (PID, FD) tuple. The TlsPoller groups them by stream key and
// delivers complete reassembled data to the registered handler.
type TlsPoller struct {
	chunksReader   *perf.Reader
	onChunk        func(*events.TlsChunkEvent)
	reusableRecord perf.Record

	wg sync.WaitGroup

	stats TlsPollerStats
}

// TlsPollerStats tracks operational counters for diagnostics.
type TlsPollerStats struct {
	ChunksGot     uint64
	ChunksHandled uint64
	ChunksLost    uint64
}

// NewTlsPoller creates a TlsPoller attached to the given perf buffer map.
// onChunk is called synchronously for each successfully decoded TlsChunkEvent.
// perfBufferSize controls the per-CPU ring size for the perf reader (bytes).
func NewTlsPoller(perfBuffer *ebpf.Map, onChunk func(*events.TlsChunkEvent), perfBufferSize int) (*TlsPoller, error) {
	reader, err := perf.NewReader(perfBuffer, perfBufferSize)
	if err != nil {
		return nil, fmt.Errorf("TlsPoller: perf.NewReader: %w", err)
	}

	return &TlsPoller{
		chunksReader: reader,
		onChunk:      onChunk,
	}, nil
}

// Start launches the polling goroutine. Non-blocking.
func (p *TlsPoller) Start() {
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		p.poll()
	}()
}

// Stop closes the perf reader, causing the poll goroutine to exit.
func (p *TlsPoller) Stop() error {
	err := p.chunksReader.Close()
	p.wg.Wait()
	return err
}

// Stats returns a snapshot of the current operational counters.
func (p *TlsPoller) Stats() TlsPollerStats {
	return TlsPollerStats{
		ChunksGot:     atomic.LoadUint64(&p.stats.ChunksGot),
		ChunksHandled: atomic.LoadUint64(&p.stats.ChunksHandled),
		ChunksLost:    atomic.LoadUint64(&p.stats.ChunksLost),
	}
}

// poll is the main polling loop. Drains the perf buffer and dispatches
// each chunk to the registered onChunk handler.
func (p *TlsPoller) poll() {
	// Drain stale records left from before startup to avoid processing old data.
	p.chunksReader.SetDeadline(time.Unix(1, 0))
	var emptyRecord perf.Record
	for {
		if err := p.chunksReader.ReadInto(&emptyRecord); errors.Is(err, os.ErrDeadlineExceeded) {
			break
		} else if err != nil {
			return
		}
	}
	p.chunksReader.SetDeadline(time.Time{})

	for {
		if err := p.chunksReader.ReadInto(&p.reusableRecord); err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			// Fatal I/O error — log and return.
			log.Printf("TlsPoller: perf read error: %v", err)
			return
		}

		if p.reusableRecord.LostSamples != 0 {
			atomic.AddUint64(&p.stats.ChunksLost, p.reusableRecord.LostSamples)
			continue
		}
		atomic.AddUint64(&p.stats.ChunksGot, 1)

		chunk, err := p.decodeChunk(p.reusableRecord.RawSample)
		if err != nil {
			continue
		}

		if p.onChunk != nil {
			p.onChunk(chunk)
		}
		atomic.AddUint64(&p.stats.ChunksHandled, 1)
	}
}

// decodeChunk parses raw perf sample bytes into a TlsChunkEvent.
// Uses binary.Read for correct alignment-independent decoding.
func (p *TlsPoller) decodeChunk(raw []byte) (*events.TlsChunkEvent, error) {
	// Fast validation: minimum header size check.
	const minSize = 88 // tlsChunkHeaderSize from events/tls_chunk_event.go
	if len(raw) < minSize {
		return nil, fmt.Errorf("TLS chunk too short: %d < %d", len(raw), minSize)
	}

	// Use the existing parser in the events package which handles the
	// BPF struct layout exactly.
	chunk, err := events.ParseTlsChunkEvent(raw)
	if err != nil {
		return nil, fmt.Errorf("TlsPoller decode: %w", err)
	}

	return chunk, nil
}
