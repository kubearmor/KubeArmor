package stream

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/kubearmor/KubeArmor/KubeArmor/apiObserver/protocols/grpc"
	"github.com/kubearmor/KubeArmor/KubeArmor/apiObserver/protocols/http2"
)
 
// WORK IN PROGRESS - gRPC/HTTP2 

// serializeHTTP2Message converts HTTP/2 message to readable format
func serializeHTTP2Message(msg *http2.Message) []byte {
	var buf bytes.Buffer

	if msg.IsRequest {
		fmt.Fprintf(&buf, "%s %s HTTP/2.0\r\n", msg.Method, msg.Path)
	} else {
		fmt.Fprintf(&buf, "HTTP/2.0 %s\r\n", msg.Status)
	}

	for k, v := range msg.Headers {
		if !strings.HasPrefix(k, ":") {
			fmt.Fprintf(&buf, "%s: %s\r\n", k, v)
		}
	}

	buf.WriteString("\r\n")
	buf.Write(msg.Body)

	return buf.Bytes()
}

// serializeGRPCMessage converts gRPC message to readable format
func serializeGRPCMessage(grpcMsg *grpc.Message) []byte {
	var buf bytes.Buffer

	if grpcMsg.IsRequest {
		fmt.Fprintf(&buf, "POST /%s/%s HTTP/2.0\r\n",
	grpcMsg.ServiceName, grpcMsg.MethodName)
	} else {
		buf.WriteString("HTTP/2.0 200\r\n")
	}

	buf.WriteString("content-type: application/grpc\r\n")

	for k, v := range grpcMsg.Headers {
		if !strings.HasPrefix(k, ":") {
			fmt.Fprintf(&buf, "%s: %s\r\n", k, v)
		}
	}

	fmt.Fprintf(&buf, "\r\n[gRPC %s: %d bytes]",
	grpcMsg.MethodName, len(grpcMsg.RawBody))

	return buf.Bytes()
}

// serializeGRPCTrailer converts gRPC trailer to readable format
func serializeGRPCTrailer(msg *http2.Message) []byte {
	var buf bytes.Buffer
	buf.WriteString("HTTP/2.0 " + msg.Status + "\r\n")
	for k, v := range msg.Headers {
		if !strings.HasPrefix(k, ":") {
			fmt.Fprintf(&buf, "%s: %s\r\n", k, v)
		}
	}
	buf.WriteString("\r\n")
	return buf.Bytes()
}
