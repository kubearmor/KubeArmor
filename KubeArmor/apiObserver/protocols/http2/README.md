# HTTP/2 & gRPC Traffic Capture in KubeArmor API Observer

This document describes how the KubeArmor API Observer captures HTTP/2 and gRPC traffic, the architecture of the implementation and known limitations.  

---

## Work Done

The API Observer provides **transparent, sidecar-free** visibility into HTTP/2 and gRPC request/response flows using only eBPF and uprobes:

- Capture method, path, authority, status, headers, and body (up to a safe limit).
- Handle **multiplexed HTTP/2 streams** correctly.
- Recover **gRPC service and method names**.
- Work even when traces start **mid-connection** (HPACK dynamic tables already populated).
- Minimize per-connection memory, suitable for always-on security monitoring.

---

## 2. High-Level Architecture

### 2.1 Data Flow Overview

At a high level, the HTTP/2/gRPC pipeline looks like this:

1. **Kernel BPF layer**
   - Syscall kprobes on `write`, `writev`, `sendto`, `sendmsg`, `read`, `readv`, `recvfrom`, `recvmsg` capture plaintext payloads at the POSIX boundary.
   - A TCP state tracepoint (`sock:inet_sock_set_state`) and connect/accept/close kprobes maintain a per-connection map (IPs, ports, protocol, SSL flag).
   - Lightweight in-kernel protocol inference tags events as HTTP/1.x, HTTP/2, gRPC, or unknown.
   - For Go gRPC servers/clients, uprobes on key `grpc` functions emit additional gRPC metadata (full method path, status, latency) via a dedicated ring buffer.

2. **User-space API Observer (Go)**
   - A **stream reassembler** reconstructs bidirectional TCP byte streams from BPF events.
   - Protocol-specific parsers for HTTP/1.x, HTTP/2, and gRPC operate on reassembled messages.
   - A **correlator** matches requests and responses across HTTP/1.x (FIFO queue) and HTTP/2 (by stream ID) to compute latency and build a `CorrelatedTrace`.
   - Kubernetes metadata (pod, namespace, service) is attached when available.

3. **Feeder & gRPC API**
   - The observer converts each `CorrelatedTrace` into a `pb.APIEvent` and streams it via the `APIObserverService` gRPC API.
   - Downstream consumers (CLI, dashboards, policy engines) subscribe and apply additional filtering.

### 2.2 HTTP/2 & gRPC-Specific Components

The following components are specific to HTTP/2/gRPC:

- **In-kernel HTTP/2/gRPC heuristic** (BPF): validates frame headers and looks for `grpc` in HEADERS frames to tag connections as HTTP/2 or gRPC.
- **HTTP/2 parser (`protocols/http2`)**: parses frames, maintains per-connection HPACK state, and assembles logical messages.
- **Tolerant HPACK decoder (`protocols/http2/bhpack`)**: a mid-stream-safe HPACK implementation adapted from OpenTelemetry.
- **gRPC parser (`protocols/grpc`)**: interprets HTTP/2 messages with gRPC content-types and trailers, extracting status codes and error messages.
- **Go gRPC uprobes (`BPF/apiobserver/go_http2_trace.h`)**: OTel-style probes that read `transport.Stream.Method` and status fields directly from Go runtime structs using goroutine-based correlation.

---

## 3. In-Kernel Protocol Detection for HTTP/2 & gRPC

The BPF side performs cheap, best-effort classification before handing data to user space. This reduces userspace work and allows early drops for irrelevant traffic.

### 3.1 HTTP/2 Preface & Frame Validation

For each captured payload chunk, the BPF program:

1. Checks for the **client preface** `"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"` at the start of the connection. If seen, it marks the connection as HTTP/2.
2. Validates the 9-byte HTTP/2 frame header:
   - Length ≤ 16 MB.
   - Type within the known set `[0x0..0x9]`.
   - Stream ID sanity (e.g., non-zero for data-bearing frames).

If a payload passes these checks, the connection's `protocol` field is updated to HTTP/2.

### 3.2 gRPC check

To detect gRPC at the kernel level, the BPF code looks at HEADERS frames and scans the first N bytes (currently 128) for the token `"grpc"`. If found, the connection is tagged as gRPC.

Limitations of this heuristic are documented later, but it is sufficient to:

- Route these events to the HTTP/2/gRPC pipeline in user space.
- Enable early, coarse-grained statistics by protocol.

### 3.3 Sticky Classification

Once a connection is classified as HTTP/2 or gRPC, later events falling back to `PROTO_UNKNOWN` reuse the last known classification. Packets that never match any pattern remain unknown and are dropped.

---

## 4. HTTP/2 Parsing & HPACK Handling

HTTP/2 introduces two complications compared to HTTP/1.x:

1. Frames are multiplexed: multiple streams interleave on the same TCP connection.
2. Headers are compressed with HPACK and rely on a **dynamic table** that evolves over time.

The API Observer addresses both with a per-connection parser and a tolerant HPACK decoder.

### 4.1 Per-Connection HTTP/2 Parser

The `protocols/http2.Parser` type owns all connection-level HTTP/2 state:

- One `HPACKDecoder` instance for the connection.
- A `map[streamID]StreamState` that tracks active streams.
- Connection-level settings (max frame size, header list size, window size).

For each connection, the reassembler feeds contiguous HTTP/2 bytes into `Parser.ParseFrames` which:

1. Optionally consumes the client preface.
2. Iterates over complete frames (DATA, HEADERS, CONTINUATION, SETTINGS, RST_STREAM, etc.).
3. For HEADERS/CONTINUATION:
   - Buffers header fragments across frames.
   - When `END_HEADERS` is set, decodes the HPACK block and populates pseudo-headers (`:method`, `:path`, `:scheme`, `:authority`, `:status`).
   - Aggregates header fields into a `Message` structure.
4. For DATA frames:
   - Appends body bytes to the stream's `Message.Body`.
   - Marks `IsEndStream` when `END_STREAM` is set.

A `Message` is considered *complete* when the relevant frames for that direction have arrived and `END_STREAM` is observed (or sufficient app-level information is present).

### 4.2 Mid-Stream HPACK Problem

The critical issue is that BPF often attaches *after* a connection has been established and has already exchanged headers. By then, the HPACK dynamic table is non-empty, but the decoder's view is empty.

With the stock Go `hpack.Decoder` this leads to:

- `invalid indexed representation index XXX` errors for any header that references a dynamic-table entry inserted before tracing started.
- These errors are **fatal**: the decoder aborts, the stream state is dropped, and subsequent DATA frames are processed as if there were no headers. Result: events with body but **no method/path/status**.

### 4.3 Tolerant HPACK Decoder (bhpack)

To fix this, the observer replaces the stock decoder with **OpenTelemetry's tolerant HPACK implementation** (`bhpack.Decoder`):

- On invalid dynamic-table references, it emits a `HeaderField{Name: "BAD INDEX", Value: ...}` sentinel instead of returning an error.
- It sets an internal `failedToIndex` flag to avoid polluting the dynamic table further.
- It still decodes all **static-table** entries and literal headers correctly.

This unlocks several important properties:

- Pre-existing connections still yield correct values for `:method`, `:path`, and `:status` when those are encoded via the static table or as literals.
- `content-type: application/grpc` is preserved, enabling gRPC classification even mid-stream.
- Dynamic-table-only headers might be marked as `BAD INDEX`, but the critical routing fields (`method`, `path`, `status`) are almost always recoverable.

### 4.4 Per-Direction HPACK State

HTTP/2 requires **separate HPACK dynamic tables for each direction of a connection** (client→server vs server→client). A bug in early versions of the observer used a single `Parser`/decoder instance for both directions, which caused subtle corruption:

- Request and response header blocks would be fed into the same decoder.
- Dynamic-table updates from one direction polluted the state for the other.
- Pseudo-headers like `:path` and `:status` would silently decode to wrong values or disappear.

The fix is to maintain **two parsers per connection**:

- `h2Send` for egress (local → remote) direction.
- `h2Recv` for ingress (remote → local) direction.

The connection tracker selects the appropriate parser based on the BPF event's direction and calls `ParseFrames` on the corresponding instance. Each parser owns its own HPACK dynamic table, as the spec expects.

### 4.5 Request vs Response Classification

Initial implementations inferred whether a message was a request or response based on the presence of `:method` vs `:status` pseudo-headers. This breaks down when HPACK decoding fails for either header.

The current logic instead trusts the **BPF direction flag**:

- For **server-side** observation (kprobes attached in the server pod):
  - Ingress (remote → local): requests.
  - Egress (local → remote): responses.
- For **client-side** observation:
  - Egress: requests.
  - Ingress: responses.

The header-based heuristic is kept only as a fallback when direction information is ambiguous.

---

## 5. gRPC Support

gRPC runs on top of HTTP/2 but introduces its own conventions:

- `:path` is of the form `/package.Service/Method`.
- `content-type` is typically `application/grpc` or variants.
- Status and error information are carried in trailers (`grpc-status`, `grpc-message`).

### 5.1 Kernel-Side Detection

At the kernel level, gRPC is inferred from:

- HTTP/2 classification (preface/frame validation), and
- Presence of `"grpc"` in the HEADERS block within the first N bytes (usually via `content-type` or trailer keys).

This is a heuristic; user-space parsing refines it.

### 5.2 User-Space gRPC Parser

Once an HTTP/2 message is reconstructed, the gRPC parser:

- Checks `Content-Type` for `application/grpc` (including protobuf and JSON variants).
- Parses the HTTP/2 message body according to the gRPC framing (5-byte length-prefixed messages for unary/streaming RPCs).
- Looks at headers and trailers to extract:
  - `grpc-status` (integer code).
  - `grpc-message` (human-readable error).

These values are stored alongside the HTTP-level fields in `PendingRequest` and `CorrelatedTrace`.

### 5.3 Go gRPC Uprobes (OTel-Style)

HTTP/2 header-based extraction is often insufficient to find the exact gRPC method path, especially for mid-stream connections and stripped binaries. Pixie attempted to solve this by walking Go interface chains to recover FDs and decoding HPACK in BPF, but that approach fails in many real deployments.

KubeArmor instead reuses the approach from **OpenTelemetry's Go eBPF tracer**:

- Uprobes are attached to key Go functions such as:
  - `(*grpc.Server).handleStream` (server-side).
  - `(*ClientConn).Invoke` and `(*ClientConn).NewStream` (client-side).
  - `(*http2Server).WriteStatus` (status/trailers).
- The current **goroutine pointer** is read from a known TLS register, providing a stable correlation key within the Go runtime.
- A small BPF map keyed by `{goroutine_addr, pid}` stores:
  - Start timestamp.
  - Pointer to the `transport.Stream` or client call context.
- On function return, the probe reads:
  - `transport.Stream.Method` (a Go string) to get the full `/package.Service/Method` path.
  - Status codes from the relevant structs.
- A compact `gogrpcrequestevent` is emitted via a ring buffer, containing:
  - `startNs`, `endNs`.
  - `pid`.
  - `status`.
  - `eventType` (server vs client).
  - `path` (null-terminated C string).

On the Go side, `events.ParseGoGRPCRequestEvent` decodes these samples and exposes convenience helpers like `LatencyNs()` and `IsServer()`.

### 5.4 Correlator Integration

There are two integration points with the correlator:

1. **HTTP/2 stream-level enrichment**
   - A `InjectGoHTTP2Headers` method merges headers from Go uprobes into pending HTTP/2 requests keyed by `{ConnectionKey, StreamID}`.
   - Uprobe-derived fields take precedence for pseudo-headers (`:method`, `:path`) because they are guaranteed correct post-HPACK decoding.
   - If no request exists yet, the correlator creates a placeholder from uprobe headers so that an eventual response can still be matched.

2. **Standalone gRPC events**
   - `InjectGoGRPCEvent` handles events where the uprobe alone provides a complete view (path, status, latency) independent of the kprobe pipeline.
   - These are emitted as synthetic `CorrelatedTrace` instances even if stream-level kprobe data is missing.

This hybrid model allows the system to:

- Use socket-level parsing as the default.
- Upgrade events with Go-specific metadata when available.
- Still function for non-Go gRPC servers (e.g., Java, C++, Rust) using only the HTTP/2 pipeline.

---

## 6. Request/Response Correlation for HTTP/2/gRPC

Correctly matching requests and responses is critical for latency measurements and higher-level flows.

### 6.1 HTTP/2 Stream Correlation

The correlator keeps per-connection state:

- `map[ConnectionKey]HTTP2StreamRequests` where each entry is `map[streamID]PendingRequest`.

On **request** message:

- Compute `ConnectionKey` (PID, FD, SockPtr) and `streamID`.
- Store a `PendingRequest` keyed by `(ConnectionKey, streamID)` with:
  - HTTP/2 pseudo-headers and normal headers.
  - Body (up to truncation limit).
  - gRPC metadata (service, method, content-type) if known.

On **response** message:

- Look up `(ConnectionKey, streamID)`.
- If found, remove the pending entry and construct a `CorrelatedTrace`:
  - `Timestamp`: request arrival time.
  - `DurationNs`: `now - request.Timestamp`.
  - `Status`: HTTP `:status` or gRPC `grpc-status` / inferred status.
  - All headers/bodies attached.

If no matching request exists, the response is counted as `unmatchedResponses` and ignored at the API level (though stats keep track for debugging).

### 6.2 Cleanup & Timeouts

To avoid unbounded state growth:

- When the TCP connection closes, `CloseConnection` flushes all pending stream entries.
- A background `cleanupLoop` evicts requests older than the configured timeout (default 30s), recording stats by cleanup reason:
  - Timeout.
  - Connection close.
  - Buffer full.

---

## 7. Body Capture & Truncation Strategy

HTTP/2/gRPC payloads can be large (e.g., big JSON, large protobuf messages). Simply buffering entire bodies, as Pixie does, is not acceptable in a security runtime that runs on every node.

KubeArmor's API Observer uses a middle-ground approach:

- Per-direction HTTP buffer: **128 KiB** (256 KiB per connection total).
- Body capture limit: **124 KiB** for body bytes **only**; headers are never truncated.
- When the body cap is reached, the parser:
  - Emits the event immediately with `Body` containing the first 124 KiB.
  - Sets a truncation flag.
  - Signals the reassembler to **skip** the remaining body bytes from the wire using an explicit `skipBytes` counter, keeping the stream aligned for the next message.

This differs from:

- **Pixie** — buffers up to 50 MB per connection in userspace and then truncates body to 512 bytes.
- **OpenTelemetry eBPF** — captures only the first ~256 bytes per syscall and never stores body payloads.

For gRPC specifically:

- The 124 KiB cap applies to the serialized gRPC message bytes.
- For binary MIME types (e.g., `application/octet-stream`, images, video), the body is replaced with a short marker like `[binary data omitted]` to avoid wasting buffer space.

---

## 8. Known Limitations

Despite the above, there are important limitations to be aware of:

1. **HPACK BAD INDEX entries**
   - When tracing starts mid-connection, some headers will still be decoded as `BAD INDEX`, especially those relying purely on the dynamic table.
   - In most gRPC workloads this does not affect `:method` / `:path`, but auxiliary headers may be incomplete.

2. **Heuristic gRPC detection**
   - The BPF heuristic only scans the first chunk of HEADERS data for `"grpc"`.
   - Exotic servers that push gRPC descriptors beyond that window might be misclassified as plain HTTP/2.

3. **Partial TLS coverage**
   - Full HTTPS visibility requires SSL uprobes to be attached and offsets correctly resolved for the OpenSSL/BoringSSL version in use.
   - Without working SSL uprobes, HTTP/2/gRPC over TLS will appear as encrypted and only limited metadata may be available.

4. **Go-only uprobes**
   - The goroutine-based uprobes only benefit Go gRPC binaries.
   - Non-Go services rely solely on HTTP/2 parsing; you may see correct path and status but not goroutine-level latency if the application buffers data in non-standard ways.

5. **Body truncation**
   - Bodies larger than 124 KiB are truncated.
   - For large streaming RPCs, you only see the initial portion of the payload.

6. **Mid-stream attach edge cases**
   - When BPF is attached long after a connection starts, the first few messages may be missing path/headers until HPACK dynamic-table state is rebuilt from ongoing traffic or enriched by Go uprobes.

---

## 9. TODOs & Future Work

The following improvements are planned or under discussion for the HTTP/2/gRPC path:

1. **Configurable body capture and buffer sizes**
   - Expose `maxBodyBytes` and per-connection buffer caps via configuration (similar to Pixie's env-based tuning).

2. **Configurable protocol and namespace filters**
   - Move BPF-side port and path filters to maps to allow runtime configuration.
   - Expose per-namespace includes/excludes for API traffic.

3. **Better mid-stream recovery**
   - Use gRPC uprobes to retroactively patch BAD INDEX placeholders when later events expose the full path.
   - Consider persisting some HPACK tables across short-lived restarts when safe.

4. **Richer gRPC semantics**
   - Distinguish between unary and streaming RPCs in the event schema.
   - Surface message counts and aggregate payload sizes per stream.

5. **Testing matrix expansion**
   - Systematic coverage of different gRPC languages (Java, C++, Python, Rust) and intermediaries (Envoy, Istio) to harden classification and parsing.

---

## 10. Relevant Code Sections

This section lists the most relevant files for HTTP/2/gRPC implementation.

### 10.1 BPF Layer

- `BPF/apiobserver/protocol_inference.h`
  - In-kernel HTTP/2 preface/frame validation and gRPC heuristic.
- `BPF/apiobserver/go_http2_trace.h`
  - Go gRPC uprobes; goroutine-based correlation; event struct layout for `gogrpcrequestevent`.

### 10.2 User-Space Parsers & Reassembly

- `apiObserver/stream_reassembler.go`
  - TCP stream reassembly; per-connection buffers; protocol dispatch.
- `apiObserver/protocols/http2/*.go`
  - `parser.go`: HTTP/2 frame parsing and stream tracking.
  - `hpack.go`: wrapper around tolerant HPACK decoder.
  - `bhpack/*`: HPACK implementation adapted from OpenTelemetry, including static table and Huffman decoding.
- `apiObserver/protocols/grpc/parser.go`
  - gRPC message parsing and trailer handling.

### 10.3 Events & Correlation

- `apiObserver/events/events.go`
  - `DataEvent` representation and parsing from the BPF ring buffer.
- `apiObserver/events/go_header_event.go`
  - Decoding of gRPC uprobe events (`GoGRPCRequestEvent`).
- `apiObserver/events/types.go`
  - `PendingRequest`, `CorrelatedTrace`, and HTTP/2 stream-tracking structs.
- `apiObserver/events/correlator.go`
  - `AddHTTP2Request`, `MatchHTTP2Response`, `InjectGoHTTP2Headers`, and `InjectGoGRPCEvent` implementations.

### 10.4 Filters & Enrichment

- `apiObserver/filter/filterer.go`
  - Basic filtering of health checks, loopback/host traffic, and namespace-level policies.
- `apiObserver/watcher.go`
  - (Planned) Kubernetes metadata enrichment (IP → pod/service resolution).

