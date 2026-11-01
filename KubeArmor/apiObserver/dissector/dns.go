// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package dissector

import (
	"encoding/binary"
	"fmt"
	"strings"
	"sync"

	pb "github.com/accuknox/SentryFlow/protobuf/golang"
)

// dnsBuilderPool reuses strings.Builder instances across parseDNSName calls
// to eliminate the []string + strings.Join allocation hot path.
var dnsBuilderPool = sync.Pool{New: func() any { return new(strings.Builder) }}

// processDNS attempts to parse the payload as a DNS query or response
// and emits an APIEvent if successful.
// For UDP, payload is the DNS message.
// For TCP, the first 2 bytes are the length of the DNS message, followed by the message.
func (d *Dissector) processDNS(info streamInfo, payload []byte) {
	if info.proto == 6 { // TCP
		if len(payload) < 2 {
			return
		}
		msgLen := int(binary.BigEndian.Uint16(payload[0:2]))
		if len(payload) < 2+msgLen {
			return
		}
		payload = payload[2 : 2+msgLen]
	}

	if len(payload) < 12 {
		return // Too short for DNS header
	}

	// transactionID := binary.BigEndian.Uint16(payload[0:2])
	flags := binary.BigEndian.Uint16(payload[2:4])
	qdcount := binary.BigEndian.Uint16(payload[4:6])
	ancount := binary.BigEndian.Uint16(payload[6:8])

	isResponse := (flags & 0x8000) != 0

	if qdcount == 0 {
		return // Must have at least one question
	}

	offset := 12
	queryName, offset, err := parseDNSName(payload, offset)
	if err != nil {
		return
	}

	if offset+4 > len(payload) {
		return
	}
	qtype := binary.BigEndian.Uint16(payload[offset : offset+2])
	// qclass := binary.BigEndian.Uint16(payload[offset+2 : offset+4])
	offset += 4

	protoStr := "DNS/UDP"
	if info.proto == 6 {
		protoStr = "DNS/TCP"
	}

	evt := &pb.APIEvent{
		Source: &pb.Workload{
			Ip:   info.srcIP,
			Port: int32(info.srcPort),
		},
		Destination: &pb.Workload{
			Ip:   info.dstIP,
			Port: int32(info.dstPort),
		},
		Protocol: protoStr,
	}

	if !isResponse {
		evt.DnsRequest = &pb.DNSRequest{
			QueryName: queryName,
			QueryType: dnsTypeToString(qtype),
		}
	} else {
		rcode := int32(flags & 0x000F)
		rcodeName := dnsRCodeToString(rcode)

		var ips []string
		for i := 0; i < int(ancount) && offset < len(payload); i++ {
			// The RR owner name is not needed — just skip it (no allocation).
			newOffset, ok := skipDNSName(payload, offset)
			if !ok {
				break
			}
			offset = newOffset
			if offset+10 > len(payload) {
				break
			}
			rtype := binary.BigEndian.Uint16(payload[offset : offset+2])
			rdlength := int(binary.BigEndian.Uint16(payload[offset+8 : offset+10]))
			offset += 10

			if offset+rdlength > len(payload) {
				break
			}
			rdata := payload[offset : offset+rdlength]
			if rtype == 1 && rdlength == 4 { // A record
				ips = append(ips, parseIPv4(rdata))
			} else if rtype == 28 && rdlength == 16 { // AAAA record
				ips = append(ips, parseIPv6(rdata))
			}
			offset += rdlength
		}

		evt.DnsResponse = &pb.DNSResponse{
			Rcode:       rcode,
			RcodeName:   rcodeName,
			ResolvedIps: ips,
		}
	}

	if d.handler != nil {
		d.handler(evt)
	}
}

// parseDNSName parses a DNS name from payload starting at startOffset.
// It uses a pooled strings.Builder to avoid per-call []string + strings.Join allocations.
func parseDNSName(payload []byte, startOffset int) (string, int, error) {
	b := dnsBuilderPool.Get().(*strings.Builder)
	b.Reset()
	defer dnsBuilderPool.Put(b)

	offset := startOffset
	jumped := false
	maxJumps := 10
	jumps := 0
	first := true

	for {
		if offset >= len(payload) {
			return "", 0, nil
		}
		length := int(payload[offset])
		if length == 0 {
			if !jumped {
				offset++
			}
			break
		}
		if (length & 0xC0) == 0xC0 {
			if offset+1 >= len(payload) {
				return "", 0, nil
			}
			if !jumped {
				startOffset = offset + 2
			}
			offset = int(binary.BigEndian.Uint16(payload[offset:offset+2]) & 0x3FFF)
			jumped = true
			jumps++
			if jumps > maxJumps {
				return "", 0, nil
			}
			continue
		}
		offset++
		if offset+length > len(payload) {
			return "", 0, nil
		}
		if !first {
			b.WriteByte('.')
		}
		b.Write(payload[offset : offset+length])
		first = false
		offset += length
	}

	if !jumped {
		startOffset = offset
	}

	return b.String(), startOffset, nil
}

// skipDNSName advances past a (possibly compressed) DNS name starting at
// offset without building the string. Returns the offset of the first byte
// after the name and whether the name was well-formed.
func skipDNSName(payload []byte, offset int) (int, bool) {
	for {
		if offset >= len(payload) {
			return 0, false
		}
		length := int(payload[offset])
		switch {
		case length == 0:
			return offset + 1, true
		case length&0xC0 == 0xC0: // compression pointer terminates the name
			if offset+2 > len(payload) {
				return 0, false
			}
			return offset + 2, true
		default:
			offset += 1 + length
		}
	}
}

func dnsTypeToString(qtype uint16) string {
	switch qtype {
	case 1:
		return "A"
	case 2:
		return "NS"
	case 5:
		return "CNAME"
	case 12:
		return "PTR"
	case 15:
		return "MX"
	case 16:
		return "TXT"
	case 28:
		return "AAAA"
	case 33:
		return "SRV"
	default:
		return "Unknown"
	}
}

func dnsRCodeToString(rcode int32) string {
	switch rcode {
	case 0:
		return "NoError"
	case 1:
		return "FormErr"
	case 2:
		return "ServFail"
	case 3:
		return "NXDomain"
	case 4:
		return "NotImp"
	case 5:
		return "Refused"
	default:
		return "Unknown"
	}
}

func parseIPv4(rdata []byte) string {
	if len(rdata) != 4 {
		return ""
	}
	return ipv4String(rdata)
}

func parseIPv6(rdata []byte) string {
	if len(rdata) != 16 {
		return ""
	}
	return fmt.Sprintf("%x:%x:%x:%x:%x:%x:%x:%x",
		uint16(rdata[0])<<8|uint16(rdata[1]),
		uint16(rdata[2])<<8|uint16(rdata[3]),
		uint16(rdata[4])<<8|uint16(rdata[5]),
		uint16(rdata[6])<<8|uint16(rdata[7]),
		uint16(rdata[8])<<8|uint16(rdata[9]),
		uint16(rdata[10])<<8|uint16(rdata[11]),
		uint16(rdata[12])<<8|uint16(rdata[13]),
		uint16(rdata[14])<<8|uint16(rdata[15]),
	)
}
