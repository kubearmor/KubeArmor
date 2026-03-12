// Package http1 implements HTTP/1.x request and response frame parsing.
//
// Creates one parser per connection per direction:
//	  reqParser  := http1.NewParser(true)   // EGRESS  — request side
//	  respParser := http1.NewParser(false)  // INGRESS — response side

package http1

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
)

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
// Returns:
//   - msgs:      complete messages (may be empty if buf is incomplete)
//   - remaining: bytes not yet consumed (tail of an incomplete message)
//   - err:       non-nil only for an unrecoverable format violation
func (p *Parser) Parse(buf []byte) (msgs []*Message, remaining []byte, err error) {
	if len(buf) == 0 {
		return nil, nil, nil
	}

	offset := 0
	for offset < len(buf) {
		msg, consumed, parseErr := p.parseOne(buf[offset:])
		if parseErr != nil {
			// Attempt resync: scan forward for the next valid message start.
			next := FindFrameBoundary(buf[offset:], p.isRequest)
			if next <= 0 {
				return msgs, buf[offset:], parseErr
			}
			offset += next
			continue
		}
		if consumed == 0 {
			// Incomplete — need more data from the ring buffer.
			break
		}
		msgs = append(msgs, msg)
		offset += consumed
	}

	return msgs, buf[offset:], nil
}

// parseOne tries to parse exactly one HTTP/1.x message starting at buf[0].
// Returns (message, bytesConsumed, error).
// bytesConsumed == 0 means "incomplete; caller should wait for more data".
func (p *Parser) parseOne(buf []byte) (*Message, int, error) {
	headerEnd, termLen := findHeaderTerminator(buf)
	if headerEnd < 0 {
		return nil, 0, nil // headers not yet complete
	}

	headerBlock := buf[:headerEnd]
	bodyStart := headerEnd + termLen

	// parse first line
	before, after, ok := bytes.Cut(headerBlock, []byte{'\n'})
	if !ok {
		return nil, 0, fmt.Errorf("HTTP/1: no newline in header block")
	}
	firstLine := strings.TrimRight(string(before), "\r\n ")

	msg := &Message{IsRequest: p.isRequest}
	if p.isRequest {
		if err := parseRequestLine(firstLine, msg); err != nil {
			return nil, 0, err
		}
	} else {
		if err := parseStatusLine(firstLine, msg); err != nil {
			return nil, 0, err
		}
	}

	msg.Headers = parseHeaders(after)

	// determine body boundary
	totalLen, complete := bodyBoundary(msg.Headers, buf, bodyStart, p.isRequest)
	if !complete {
		return nil, 0, nil // body not yet arrived
	}

	// extract and decode body(if chunked)
	if totalLen > bodyStart {
		te := strings.ToLower(msg.Headers["transfer-encoding"])
		if strings.Contains(te, "chunked") {
			decoded, err := decodeChunked(buf[bodyStart:totalLen])
			if err != nil {
				return nil, 0, fmt.Errorf("chunked decode: %w", err)
			}
			msg.Body = decoded
		} else {
			msg.Body = make([]byte, totalLen-bodyStart)
			copy(msg.Body, buf[bodyStart:totalLen])
		}
	}

	return msg, totalLen, nil
}

func bodyBoundary(headers map[string]string, buf []byte, bodyStart int, isRequest bool) (int, bool) {
	if te, ok := headers["transfer-encoding"]; ok &&
		strings.Contains(strings.ToLower(te), "chunked") {
		end, ok := findChunkedEnd(buf, bodyStart)
		return end, ok
	}

	if cl, ok := headers["content-length"]; ok {
		n, err := strconv.Atoi(strings.TrimSpace(cl))
		if err != nil || n < 0 {
			return bodyStart, true // treat as body-less
		}
		total := bodyStart + n
		if len(buf) < total {
			return 0, false // incomplete body
		}
		return total, true
	}

	// Requests without Content-Length have no body (GET, HEAD, etc.).
	if isRequest {
		return bodyStart, true
	}

	return bodyStart, true
}

// findChunkedEnd locates the wire end of a chunked body starting at offset.
// Returns (totalWireBytes, complete).
func findChunkedEnd(buf []byte, offset int) (int, bool) {
	pos := offset
	for {
		// Read the hex chunk-size line.
		nl := bytes.IndexByte(buf[pos:], '\n')
		if nl < 0 {
			return 0, false // incomplete
		}
		line := strings.TrimRight(string(buf[pos:pos+nl]), "\r\n")
		// Strip chunk extensions (; name=value).
		if semi := strings.IndexByte(line, ';'); semi >= 0 {
			line = line[:semi]
		}
		chunkSize, err := strconv.ParseInt(strings.TrimSpace(line), 16, 64)
		if err != nil {
			return 0, false
		}
		pos += nl + 1 // advance past the '\n'

		if chunkSize == 0 {
			// Terminal chunk — consume optional trailers up to \r\n\r\n or \n\n.
			if idx := bytes.Index(buf[pos:], []byte("\r\n\r\n")); idx >= 0 {
				return pos + idx + 4, true
			}
			if idx := bytes.Index(buf[pos:], []byte("\n\n")); idx >= 0 {
				return pos + idx + 2, true
			}
			return 0, false // trailers still incomplete
		}

		// Skip chunk data + trailing CRLF.
		dataEnd := pos + int(chunkSize) + 2
		if len(buf) < dataEnd {
			return 0, false // chunk data not yet arrived
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
		body = append(body, wire[pos:pos+int(chunkSize)]...)
		pos += int(chunkSize) + 2 // skip data + CRLF
	}
	return body, nil
}

// Helpers

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
// lowercase-keyed map.  RFC 7230 §3.2.2: duplicate fields are joined with ", ".
func parseHeaders(block []byte) map[string]string {
	headers := make(map[string]string)
	for line := range bytes.SplitSeq(block, []byte("\n")) {
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
