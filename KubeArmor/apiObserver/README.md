# API Observer

The `apiObserver` package is the userspace half of KubeArmor's API-level observability pipeline. It consumes raw network data events emitted by eBPF code, reassembles them into protocol-level messages, correlates requests with responses, enriches them with Kubernetes metadata, and pushes structured `pb.APIEvent` records to external consumers via gRPC.

## Data Flow

```
BPF ring buffer (apiobserver_events)
  │
  ▼
TraceEvents goroutine ── drains raw ring buffer samples into EventsChannel (cap 4096, see note below)
  │
  ▼
ParseDataEvent ── binary decode of the 48-byte fixed header + variable payload
  │
  ▼
connManager.Route() ── per-connection lifecycle management + protocol parser dispatch
  │  ├── HTTP/1.x parser (protocols/http1)
  │  ├── HTTP/2 frame parser (protocols/http2)
  │  └── gRPC parser (protocols/grpc)
  │
  ▼
Correlator ── matches requests ↔ responses
  │  ├── HTTP/1.x: FIFO queue per connection 
  │  └── HTTP/2/gRPC: per-stream-ID map per connection 
  │
  ▼
enrichAndEmit ── filtering + K8s metadata enrichment + pb.APIEvent construction
  │
  ▼
feeder.PushAPIEvent ── gRPC fan-out to all subscribed clients
```

> **EventsChannel buffer (cap 4096)**: The Go channel between the ring buffer reader and the processing goroutine is buffered at 4096 entries. This acts as a backpressure absorber — if the processing side (parsing, correlation, enrichment) temporarily falls behind, the channel buffers events before the reader starts dropping them (via the `default` case in the select). Each entry is a `[]byte` slice (up to ~8KB due to `MAX_DATA_SIZE`), so worst-case memory is ~32MB. Can be made configurable in the future.

## Package Layout

| Subpackage | Purpose |
|---|---|
| `events/` | `DataEvent` parsing, `Correlator` interface + implementation, shared types (`ConnectionKey`, `PendingRequest`, `CorrelatedTrace`) |
| `events/conn/` | `conn.Manager` — per-socket `ConnectionTracker` lifecycle, protocol parser routing |
| `protocols/http1/` | HTTP/1.x request/response parser |
| `protocols/http2/` | HTTP/2 frame parser |
| `protocols/grpc/` | gRPC-over-HTTP/2 parser (relies on heuristic hints from BPF) |
| `filter/` | `Filterer` — request-level (path/UA) and connection-level (namespace/loopback/internal-hop) filtering |
| `stream/` | `Reassembler` — TCP stream reassembly, `Serializer` — ordered event delivery |
| `ssl/` | OpenSSL `libssl.so` discovery + `ssl_symaddrs` struct offset resolution for uprobe attachment |

## Key Components

### `APIObserver` (`apiObserver.go`)

Initialization (`NewAPIObserver`) does the following in order:

 - **Tracepoint** — attaches `inet_sock_set_state` for TCP connection lifecycle tracking.
 - **Kprobes** — attaches all syscall probes:
   - **Egress** (kprobe only): `write`, `writev`, `sendto`, `sendmsg`
   - **Ingress** (kprobe + kretprobe pairs): `read`, `readv`, `recvfrom`, `recvmsg`
   - **FD lifecycle**: `connect` (entry+return), `accept`/`accept4` (return), `close` (entry)
 - **SSL uprobes** (not attached - TODO) — attaches `uprobe`/`uretprobe` on `SSL_write` and `SSL_read` for each discovered `libssl.so`.
 - **Ring buffer reader** — creates a `ringbuf.Reader` on the `apiobserver_events` ring buffer. This is a 4 MB `BPF_MAP_TYPE_RINGBUF` — a shared-memory circular buffer between kernel and userspace. BPF programs write `data_event` structs into it via `bpf_ringbuf_reserve()` + `bpf_ringbuf_submit()`, and userspace drains it via `ringbuf.Reader.Read()`. The 4 MB size determines how much data can be buffered in kernel memory before events are dropped (tracked by `dropped_packets` stat). 
 - **Pipeline** — initializes `Filterer`, `Correlator`, and `conn.Manager`, then starts the `TraceEvents` event loop. The correlator is configured with a 30-second request-response timeout — this controls how long a pending request waits for its matching response before being evicted by the cleanup goroutine. 

Shutdown (`DestroyAPIObserver`) cancels the context, closes the ring buffer, detaches all probes, and stops the correlator cleanup goroutine.

### Correlator (`events/correlator.go`)

Implements two independent stitching algorithms:

- **HTTP/1.x (FIFO queue)** — HTTP/1.1 is a sequential protocol per connection — even with pipelining, responses must arrive in the same order as requests. So we use a simple FIFO queue per connection:
  - **On request** (`AddHTTP1Request`): the parsed request (method, URL, headers, body, timestamp) is pushed to the back of the queue. If the queue hits 256 entries (a pathological pipelining case), the oldest is evicted.
  - **On response** (`MatchHTTP1Response`): the **head** of the queue (oldest unmatched request) is popped and paired with the response. Latency is computed as `now - request.Timestamp`.
  - This correctly handles keep-alive connections (multiple sequential request-response pairs) and pipelining (multiple requests sent before any response arrives).

- **HTTP/2 / gRPC (stream-ID map)** — HTTP/2 is multiplexed — multiple independent request-response exchanges (streams) run concurrently on the same TCP connection, each identified by a unique stream ID. FIFO matching would not work here because responses can arrive in any order.
  - **On request** (`AddHTTP2Request`): the parsed request is stored in a `map[uint32]PendingRequest` keyed by stream ID, nested under the connection key.
  - **On response** (`MatchHTTP2Response`): the stream ID is looked up in the map, the pending request is removed, and they are paired into a `CorrelatedTrace`.
  - gRPC uses HTTP/2 as its transport, so it uses the same stream-ID matching. The in-kernel `is_grpc_headers_frame()` heuristic flags the connection as gRPC so userspace routes it to the gRPC parser instead of the generic HTTP/2 parser.

A background cleanup goroutine ticks every 10 seconds and evicts requests older than the configured timeout (default 30s) to prevent unbounded memory growth on half-open connections. `CloseConnection()` flushes all pending requests when a TCP_CLOSE BPF event is received.

Observable metrics include: `TotalRequests`, `MatchedPairs`, `UnmatchedResponses`, `PipelinedRequests`, `HTTP2Streams`, and per-reason eviction counts.

### Filterer (`filter/filterer.go`)

Multi-layer filtering applied in `enrichAndEmit`:

1. **Request-level** — `ShouldTraceRequest(url, ua)`: currently pass-all (TODO: configurable path exclusions).
2. **Health probe detection** — `IsHealthProbe(url, ua, body)`: suppresses Kubernetes probes by URL prefix (`/healthz`, `/readyz`, `/livez`, `/health`), User-Agent (`kube-probe/`, `GoogleHC/`), and response body pattern (`"health":[`).
3. **Loopback** — `IsLoopbackTraffic(src, dst)`: drops `127.0.0.0/8` ↔ `127.0.0.0/8`.
4. **Namespace** — `ShouldTraceConnection(...)`: drops traffic entirely within `kube-system`.
5. **Internal hop** *(needs refinement)* — `IsInternalHop(...)`: if both source and destination are resolved pods in different namespaces, the event is assumed to be a duplicate observation of a cross-service hop and is dropped. The rationale is that when kprobes are attached system-wide, a single API call like `frontend → backend` on the same node can be captured twice (once at the frontend's `write()` and once at the backend's `read()`). However, this filter is aggressive — it also drops legitimate cross-namespace communication. Pixie solves this differently via `{PID, FD}` keying to deduplicate at the connection tracker level rather than by filtering. **This is a known heuristic that should be revisited and likely made configurable.**

### Watcher (`watcher.go`)

Provides IP-to-workload metadata resolution:

- `GetPodURI(ip)` → `"namespace/pod-name"` or `""`
- `GetServicesByIP(ip)` → `[]ServiceInfo{Name, Namespace}`

**Status**: TODO: currenlty returns raw IPs 

### Event parsing (`events/events.go`)

`ParseDataEvent([]byte)` decodes ring buffer samples into `DataEvent` structs. The 48-byte fixed header layout matches `struct data_event` in `BPF/apiobserver/common/structs.h` exactly:
Each event derives a `ConnectionKey{PID, FD, SockPtr}` for Pixie-style `{tgid, fd}` keying. When FD is 0 (missed `connect`/`accept` probes), `SockPtr` serves as fallback.

## Output Format

Events are emitted as `pb.APIEvent` messages using the [SentryFlow](https://github.com/accuknox/SentryFlow) protobuf schema. Each event includes:

- **Metadata**: timestamp, node name, receiver name ("KubeArmor")
- **Source / Destination**: workload name, namespace, IP, port
- **Request**: method, path, headers, body
- **Response**: status code, headers, body
- **Protocol**: `HTTP1.x`, `HTTP2`, or `gRPC`
- **Latency**: request-response duration in nanoseconds
