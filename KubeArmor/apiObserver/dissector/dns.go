// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package dissector

import (
	"encoding/binary"
	"fmt"
	"strings"

	pb "github.com/accuknox/SentryFlow/protobuf/golang"
)

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
		evt.Req = &pb.APIEvent_DnsRequest{DnsRequest: &pb.DNSRequest{
			QueryName: queryName,
			QueryType: dnsTypeToString(qtype),
		}}
	} else {
		rcode := int32(flags & 0x000F)
		rcodeName := dnsRCodeToString(rcode)
		
		var ips []string
		for i := 0; i < int(ancount) && offset < len(payload); i++ {
			_, newOffset, err := parseDNSName(payload, offset)
			if err != nil {
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

		evt.Res = &pb.APIEvent_DnsResponse{DnsResponse: &pb.DNSResponse{
			Rcode:       rcode,
			RcodeName:   rcodeName,
			ResolvedIps: ips,
		}}
	}

	if d.handler != nil {
		d.handler(evt)
	}
}

func parseDNSName(payload []byte, startOffset int) (string, int, error) {
	var parts []string
	offset := startOffset
	jumped := false
	maxJumps := 10
	jumps := 0

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
		parts = append(parts, string(payload[offset:offset+length]))
		offset += length
	}

	if !jumped {
		startOffset = offset
	}

	return strings.Join(parts, "."), startOffset, nil
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
	return fmt.Sprintf("%d.%d.%d.%d", rdata[0], rdata[1], rdata[2], rdata[3])
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
