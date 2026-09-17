// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

// Package dissector provides the network packet dissection pipeline for the
// API Observer.
//
// It receives two types of input:
//   - RawPacket events from the PacketsPoller (plain traffic captured via
//     cgroup_skb/ingress + cgroup_skb/egress hooks).
//   - TlsChunkEvent events from the TlsPoller (TLS plaintext captured via
//     OpenSSL/Go uprobes).
//
// Both inputs are fed into a shared TCP stream reassembler that reconstructs
// HTTP/1.x and HTTP/2 sessions, then emits correlated request+response pairs
// as pb.APIEvent protobufs.
//
// Architecture follows Kubeshark Tracer's gopacket-based dissection pipeline.
package dissector
