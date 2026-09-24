// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

// Package poller provides eBPF event pollers that drain raw BPF output buffers
// and deliver typed Go structures to the dissection pipeline.
//
// architecture:
//   - TlsPoller: drains ks_chunks_buffer (perf array) and reconstructs
//     TCP streams from TLS plaintext chunks emitted by OpenSSL/Go uprobes.
//   - PacketsPoller: drains ka_pkts_buffer (perf array) and reassembles
//     raw network packets from cgroup_skb chunks.
//
// Both pollers deliver parsed gopacket.Packet objects to the dissector.
package poller
