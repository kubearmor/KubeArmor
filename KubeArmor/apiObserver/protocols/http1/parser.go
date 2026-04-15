// Package http1 implements HTTP/1.x request and response frame parsing.
//
// Creates one parser per connection per direction:
//   reqParser  := http1.NewParser(true)  // EGRESS  — request side
//   respParser := http1.NewParser(false) // INGRESS — response side

package http1

import (
	"bytes"
	"fmt"
	"math"
	"strconv"
	"strings"
)

// maxBodyBytes is the per-message body cap. Bodies exceeding this limit are
// truncated: the first maxBodyBytes are captured, the rest are drained
// off the wire via DataStreamBuffer.SkipNextBytes.
// The limit applies to body bytes only — headers are always fully captured.
const maxBodyBytes = 124 * 1024 // 124KB

// minChunkedEmitBytes is the minimum body bytes we need before emitting a
// partial chunked response. For streaming endpoints (e.g. /stream/N) the
// terminal 0\r\n chunk may never arrive within a useful timeframe. Once
// we have this many decoded body bytes, emit with truncation.
// Set low (512B) to catch small-count streams like /stream/10 (~1KB total).
const minChunkedEmitBytes = 512

// Message is one complete HTTP/1.x request or response frame.
type Message struct {
	IsRequest   bool
	HTTPVersion string // "HTTP/1.0" or "HTTP/1.1"

	// Request fields (IsRequest == true).
	Method string
	Path   string

	// Response fields (IsRequest == false).
	StatusCode int
	StatusText string

	Headers map[string]string
	Body    []byte
}

type Parser struct {
	isRequest bool
}

func NewParser(isRequest bool) *Parser {
	return &Parser{isRequest: isRequest}
}

// Parse attempts to extract one or more complete HTTP/1.x messages from buf.
//
// Parse attempts to extract one or more complete HTTP/1.x messages from buf.
//
// Returns:
//   - msgs:      complete messages parsed from buf
//   - consumed:  bytes consumed from the front of buf (call buf.Advance(consumed))
//   - skipBytes: bytes to drain from the wire after consumed (call buf.SkipNextBytes(skipBytes))
//   - remaining: unconsumed bytes (tail of an incomplete message)
//   - err:       non-nil only for an unrecoverable format violation
func (p *Parser) Parse(buf []byte) (msgs []*Message, consumed int, skipBytes int, remaining []byte, err error) {
	if len(buf) == 0 {
		return nil, 0, 0, nil, nil
	}
	offset := 0
	totalSkip := 0
	for offset < len(buf) {
		msg, n, skip, parseErr := p.parseOne(buf[offset:])
		if parseErr != nil {
			next := FindFrameBoundary(buf[offset:], p.isRequest)
			if next <= 0 {
				return msgs, offset, totalSkip, buf[offset:], parseErr
			}
			offset += next
			continue
		}
		if n == 0 {
			break
		}
		msgs = append(msgs, msg)
		offset += n
		totalSkip += skip
	}
	return msgs, offset, totalSkip, buf[offset:], nil
}

// parseOne tries to parse exactly one HTTP/1.x message starting at buf[0].
// Returns (message, bytesConsumed, skipBytes, error).
// bytesConsumed == 0 means "incomplete; wait for more data".
// skipBytes > 0 means "body was truncated; drain this many bytes from wire".
func (p *Parser) parseOne(buf []byte) (*Message, int, int, error) {
	headerEnd, termLen := findHeaderTerminator(buf)
	if headerEnd < 0 {
		return nil, 0, 0, nil
	}
	headerBlock := buf[:headerEnd]
	bodyStart := headerEnd + termLen

	before, after, ok := bytes.Cut(headerBlock, []byte{'\n'})
	if !ok {
		return nil, 0, 0, fmt.Errorf("HTTP/1: no newline in header block")
	}

	firstLine := strings.TrimRight(string(before), "\r\n ")

	msg := &Message{IsRequest: p.isRequest}
	if p.isRequest {
		if err := parseRequestLine(firstLine, msg); err != nil {
			return nil, 0, 0, err
		}
	} else {
		if err := parseStatusLine(firstLine, msg); err != nil {
			return nil, 0, 0, err
		}
	}

	msg.Headers = parseHeaders(after)

	totalLen, complete, truncated, skipBytes := bodyBoundary(msg.Headers, buf, bodyStart, p.isRequest)
	if !complete {
		return nil, 0, 0, nil
	}

	if totalLen > bodyStart {
		te := strings.ToLower(msg.Headers["transfer-encoding"])
		if strings.Contains(te, "chunked") {
			decoded, err := decodeChunked(buf[bodyStart:totalLen])
			if err != nil && !truncated {
				return nil, 0, 0, fmt.Errorf("chunked decode: %w", err)
			}
			// Cap decoded body to maxBodyBytes (chunked bodies are decoded
			// into plain bytes; the cap must be re-applied after decoding).
			if len(decoded) > maxBodyBytes {
				decoded = decoded[:maxBodyBytes]
				truncated = true
			}
			msg.Body = decoded
		} else {
			bodyLen := totalLen - bodyStart
			if truncated && bodyLen > maxBodyBytes {
				bodyLen = maxBodyBytes
			}
			msg.Body = make([]byte, bodyLen)
			copy(msg.Body, buf[bodyStart:bodyStart+bodyLen])
		}
	}

	if truncated {
		contentType := strings.ToLower(msg.Headers["content-type"])
		isBinary := strings.Contains(contentType, "application/octet-stream") ||
			strings.Contains(contentType, "application/pdf") ||
			strings.Contains(contentType, "image/") ||
			strings.Contains(contentType, "video/") ||
			strings.Contains(contentType, "audio/")
		if isBinary {
			msg.Body = []byte("[binary data omitted]")
		} else {
			msg.Body = append(msg.Body, []byte("\n... [truncated]")...)
		}
	}

	return msg, totalLen, skipBytes, nil
}

// bodyBoundary determines the wire boundary of the HTTP body.
//
// Returns (totalLen, complete, truncated, skipBytes):
//   - totalLen:  byte offset in buf where this message ends (parser should
//     consume buf[0:totalLen])
//   - complete:  true when enough data is available to emit the message
//   - truncated: true when the body was capped at maxBodyBytes
//   - skipBytes: number of bytes still in-flight on the wire that belong to
//     this body but were not captured. Caller must drain these via
//     DataStreamBuffer.SkipNextBytes(skipBytes) to stay aligned
//     for the next HTTP message.
//
// The body cap (maxBodyBytes = 124KB) applies to body bytes ONLY. Headers
// are never counted toward this limit and are always fully captured.
func bodyBoundary(headers map[string]string, buf []byte, bodyStart int, isRequest bool) (totalLen int, complete bool, truncated bool, skipBytes int) {

	if te, ok := headers["transfer-encoding"]; ok &&
		strings.Contains(strings.ToLower(te), "chunked") {
		end, ok, trunc := findChunkedEnd(buf, bodyStart)
		if trunc {
			// For chunked encoding we cannot know the exact remaining body
			// byte count (the chunk framing of the unseen bytes is unknown).
			// Use math.MaxInt32 as a sentinel; DataStreamBuffer.SkipNextBytes
			// will drain until the skip counter is exhausted. The next valid
			// HTTP message start will re-synchronise the connection naturally
			// via the circuit breaker or connection close.
			return end, ok, trunc, math.MaxInt32
		}
		if !ok {
			// Streaming fallback: if we have enough decoded body bytes
			// (minChunkedEmitBytes) but no terminal chunk yet, emit a
			// partial response. This handles streaming endpoints like
			// /stream/N that send chunks over a long period.
			bodyBytes := len(buf) - bodyStart
			if bodyBytes >= minChunkedEmitBytes {
				return len(buf), true, true, math.MaxInt32
			}
		}
		return end, ok, trunc, 0
	}

	if cl, ok := headers["content-length"]; ok {
		n, err := strconv.Atoi(strings.TrimSpace(cl))
		if err != nil || n < 0 {
			// Malformed Content-Length — treat as body-less and move on.
			return bodyStart, true, false, 0
		}

		if n > maxBodyBytes {
			// Body exceeds the cap. BPF captures at most 8KB per tcp_sendmsg
			// event, so for large responses sent in a single write(), the
			// full body is unrecoverable. Emit immediately with whatever
			// body data we have, truncate, and drain the rest from the wire.
			total := bodyStart + n
			// If buffer holds the entire message, consume it all.
			if len(buf) >= total {
				return total, true, true, 0
			}
			// Otherwise consume everything in buffer and skip the remainder.
			return len(buf), true, true, total - len(buf)
		}

		// Normal path: body is within cap. However, if we have at least the
		// header + some body (minChunkedEmitBytes) but not the full content,
		// and the body is moderately large, emit what we have. BPF may not
		// capture all segments of a multi-KB response.
		total := bodyStart + n
		if len(buf) < total {
			// If we have enough body to be useful but not all, emit partial.
			bodyInBuf := len(buf) - bodyStart
			if bodyInBuf >= minChunkedEmitBytes && n > 8192 {
				return len(buf), true, true, total - len(buf)
			}
			return 0, false, false, 0
		}
		return total, true, false, 0
	}

	// Requests without Content-Length have no body (GET, HEAD, etc.).
	// Responses without Content-Length or Transfer-Encoding are treated as
	// body-less (connection-close bodies are not common in observed traffic
	// and cannot be safely truncated without knowing the total length).
	return bodyStart, true, false, 0
}

// findChunkedEnd locates the wire end of a chunked body starting at offset.
// Returns (totalWireBytes, complete, truncated).
//
// The body cap (maxBodyBytes) is applied to body bytes only. The `offset`
// parameter is bodyStart — the byte index in buf where the body begins.
// We measure body consumption as `pos - offset` so headers are never
// counted toward the cap.
func findChunkedEnd(buf []byte, offset int) (int, bool, bool) {
	pos := offset
	for {
		// Truncate when we've consumed more body bytes than the cap allows.
		// pos - offset = body bytes parsed so far (excludes headers).
		// Return len(buf) to consume all trailing chunked payload currently in the buffer.
		if pos-offset > maxBodyBytes {
			return len(buf), true, true
		}

		nl := bytes.IndexByte(buf[pos:], '\n')
		if nl < 0 {
			if pos-offset > maxBodyBytes {
				return len(buf), true, true
			}
			return 0, false, false
		}

		line := strings.TrimRight(string(buf[pos:pos+nl]), "\r\n")
		if semi := strings.IndexByte(line, ';'); semi >= 0 {
			line = line[:semi]
		}
		chunkSize, err := strconv.ParseInt(strings.TrimSpace(line), 16, 64)
		if err != nil {
			if pos-offset > maxBodyBytes {
				return len(buf), true, true
			}
			return 0, false, false
		}
		pos += nl + 1

		if chunkSize == 0 {
			if idx := bytes.Index(buf[pos:], []byte("\r\n\r\n")); idx >= 0 {
				return pos + idx + 4, true, false
			}
			if idx := bytes.Index(buf[pos:], []byte("\n\n")); idx >= 0 {
				return pos + idx + 2, true, false
			}
			if pos-offset > maxBodyBytes {
				return len(buf), true, true
			}
			return 0, false, false
		}

		dataEnd := pos + int(chunkSize) + 2
		if len(buf) < dataEnd {
			// Not enough data yet. Check if we're already over the cap.
			if pos-offset > maxBodyBytes || dataEnd-offset > maxBodyBytes {
				return len(buf), true, true
			}
			return 0, false, false
		}
		pos = dataEnd
	}
}

// decodeChunked decodes chunked-encoded wire bytes into a plain body slice.
// Called only after findChunkedEnd confirmed the data is complete.
func decodeChunked(wire []byte) ([]byte, error) {
	var body []byte
	pos := 0
	for {
		nl := bytes.IndexByte(wire[pos:], '\n')
		if nl < 0 {
			break
		}

		line := strings.TrimRight(string(wire[pos:pos+nl]), "\r\n")
		if semi := strings.IndexByte(line, ';'); semi >= 0 {
			line = line[:semi]
		}

		chunkSize, err := strconv.ParseInt(strings.TrimSpace(line), 16, 64)
		if err != nil {
			return nil, fmt.Errorf("bad chunk size %q: %w", line, err)
		}

		pos += nl + 1
		if chunkSize == 0 {
			break
		}

		endData := pos + int(chunkSize)
		if endData > len(wire) {
			body = append(body, wire[pos:]...)
			break // Truncated body
		}

		body = append(body, wire[pos:endData]...)
		pos = endData + 2 // skip data + CRLF
		if pos >= len(wire) {
			break
		}
	}
	return body, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// findHeaderTerminator locates the \r\n\r\n (or lenient \n\n) that ends the
// HTTP header section.
// Returns (index_of_start_of_terminator, length_of_terminator).
func findHeaderTerminator(buf []byte) (int, int) {
	if idx := bytes.Index(buf, []byte("\r\n\r\n")); idx >= 0 {
		return idx, 4
	}
	if idx := bytes.Index(buf, []byte("\n\n")); idx >= 0 {
		return idx, 2
	}
	return -1, 0
}

// parseRequestLine parses "METHOD path HTTP/x.y" into msg.
func parseRequestLine(line string, msg *Message) error {
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 {
		return fmt.Errorf("HTTP/1 invalid request line: %q", line)
	}
	msg.Method = parts[0]
	msg.Path = parts[1]
	if len(parts) == 3 {
		msg.HTTPVersion = parts[2]
	} else {
		msg.HTTPVersion = "HTTP/1.0"
	}
	return nil
}

// parseStatusLine parses "HTTP/x.y CODE reason-phrase" into msg.
func parseStatusLine(line string, msg *Message) error {
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 {
		return fmt.Errorf("HTTP/1 invalid status line: %q", line)
	}
	msg.HTTPVersion = parts[0]
	code, err := strconv.Atoi(parts[1])
	if err != nil {
		return fmt.Errorf("HTTP/1 invalid status code %q: %w", parts[1], err)
	}
	msg.StatusCode = code
	if len(parts) == 3 {
		msg.StatusText = parts[2]
	} else {
		msg.StatusText = strconv.Itoa(code)
	}
	return nil
}

// parseHeaders parses lines after the request/status line into a
// lowercase-keyed map. RFC 7230 §3.2.2: duplicate fields are joined with ", ".
func parseHeaders(block []byte) map[string]string {
	headers := make(map[string]string)
	for _, line := range bytes.Split(block, []byte("\n")) {
		line = bytes.TrimRight(line, "\r\n ")
		if len(line) == 0 {
			continue
		}
		before, after, ok := bytes.Cut(line, []byte{':'})
		if !ok {
			continue // malformed field; skip
		}
		key := strings.ToLower(strings.TrimSpace(string(before)))
		val := strings.TrimSpace(string(after))
		if existing, ok := headers[key]; ok {
			headers[key] = existing + ", " + val
		} else {
			headers[key] = val
		}
	}
	return headers
}

// FindFrameBoundary scans buf[1:] for the start of the next HTTP/1.x message.
// Used for error recovery after a parse failure.
// Returns the byte offset in buf where the next candidate message starts, or -1.
func FindFrameBoundary(buf []byte, isRequest bool) int {
	if len(buf) <= 1 {
		return -1
	}

	search := buf[1:] // skip the current bad byte

	if isRequest {
		tokens := [][]byte{
			[]byte("GET "), []byte("POST "), []byte("PUT "),
			[]byte("DELETE "), []byte("PATCH "), []byte("HEAD "), []byte("OPTIONS "),
		}
		minIdx := -1
		for _, tok := range tokens {
			if idx := bytes.Index(search, tok); idx >= 0 {
				adj := idx + 1 // map back to buf coordinates
				if minIdx < 0 || adj < minIdx {
					minIdx = adj
				}
			}
		}
		return minIdx
	}

	// Responses always start with "HTTP/".
	if idx := bytes.Index(search, []byte("HTTP/")); idx >= 0 {
		return idx + 1
	}
	return -1
}
