# BPF API Observer

The `BPF/apiobserver/` directory contains all eBPF C headers that implement kernel-side network data capture for KubeArmor's API Observer. 

## Approach

### Why Syscall-Level Tracing


### Probe Attachment Points

**Syscall I/O probes** (13 total):

| Direction | Syscall | Probe Type | Why |
|---|---|---|---|
| Egress | `write` | kprobe | Standard socket write |
| Egress | `writev` | kprobe | Vectored write (Go, Node.js HTTP clients) |
| Egress | `sendto` | kprobe | Explicit destination socket write |
| Egress | `sendmsg` | kprobe | Sendmsg with `msghdr` (gRPC, HTTP/2) |
| Ingress | `read` | kprobe + kretprobe | Buffer populated on return |
| Ingress | `readv` | kprobe + kretprobe | Vectored read |
| Ingress | `recvfrom` | kprobe + kretprobe | Explicit source socket read |
| Ingress | `recvmsg` | kprobe + kretprobe | Recvmsg with `msghdr` |
| Lifecycle | `connect` | kprobe + kretprobe | Client-side FD→sock mapping |
| Lifecycle | `accept` / `accept4` | kretprobe | Server-side FD→sock mapping |
| Lifecycle | `close` | kprobe | FD cleanup |

**Tracepoint** (1):
- `sock/inet_sock_set_state` — tracks TCP state transitions (`TCP_ESTABLISHED` → populate `connections` map; `TCP_CLOSE` → cleanup all maps)

**OpenSSL uprobes** (3, TODO):
- `SSL_write` (uprobe) — intercepts plaintext before encryption
- `SSL_read` (uprobe + uretprobe) — intercepts plaintext after decryption
- Deduplication: marks connection as `is_ssl=1`, causing syscall kprobes to skip (preventing double-capture of encrypted + plaintext)

Traditional kernel network tracing hooks into `tcp_sendmsg` / `tcp_recvmsg`. This has two fundamental problems:

1. **No process context** — TCP-internal functions lose the FD and PID association, making multi-tenant correlation impossible.
2. **Encrypted payloads** — TLS encrypts data before it reaches TCP functions, so you only see ciphertext.

This implementation solves both by probing at the POSIX syscall boundary, where the process context is intact and the application has already prepared plaintext buffers.

### Syscall Wrapper Handling (x86_64)

On kernels with `CONFIG_ARCH_HAS_SYSCALL_WRAPPER=y`, `__x64_sys_*()` functions take a single argument: a pointer to the userspace `pt_regs` struct. Real syscall arguments live in `regs->di` (arg1), `regs->si` (arg2), `regs->dx` (arg3), `regs->r10` (arg4). All handlers use `get_syscall_regs()` + `syscall_arg{1..4}()` helpers for portable extraction.

Attachment tries `__x64_sys_*` first, then falls back to the unwrapped name (e.g., `ksys_write`, `sys_sendto`).

## File Layout

| File | Purpose |
|---|---|
| `common/macros.h` | Compile-time constants (directions, protocols, HTTP method signatures, frame types, limits) |
| `common/structs.h` | All shared struct definitions (`data_event`, `conn_info`, `data_args`, `conn_id`, `stats`, `ssl_*`) |
| `common/maps.h` | All BPF map definitions (ring buffer, LRU hashes, percpu arrays) |
| `conn_tracker.h` | FD→sock resolution (CO-RE fdtable walk), `connect`/`accept`/`close` handlers, `inet_sock_set_state` handler |
| `sock_trace.h` | `emit_data_event()` — shared emit core (filter cache, protocol detection, health-check suppression, ring buffer submission, stats) |
| `syscall_trace.h` | All 8 syscall I/O handlers (`handle_sys_{write,writev,sendto,sendmsg,read,readv,recvfrom,recvmsg}_{entry,return}`) with shared `egress_submit()` / `ingress_entry()` / `ingress_return()` helpers |
| `protocol_inference.h` | In-kernel protocol classification: HTTP/1 prefix matching, HTTP/2 preface + frame validation, gRPC heuristic detection |
| `filter_helpers.h` | `is_http_traffic()`, `is_health_check()`, `should_trace_port()` — early BPF-side traffic filtering |
| `openssl_trace.h` | `SSL_write` / `SSL_read` uprobe handlers, FD extraction from `SSL->rbio->num` using version-specific offsets |

## BPF Maps

| Map | Type | Key | Value | Purpose |
|---|---|---|---|---|
| `apiobserver_events` | Ring Buffer (4MB) | — | `data_event` | Event transport to userspace |
| `connections` | LRU Hash (64K) | `sock_ptr` (u64) | `conn_info` | Per-connection state (IPs, ports, protocol, SSL flag) |
| `connection_filter_cache` | LRU Hash (64K) | `sock_ptr` (u64) | `u8` (0=drop, 1=allow) | Cached filter decision per connection |
| `pid_fd_to_sock` | LRU Hash (64K) | `conn_id {tgid, fd}` | `u64` (sock_ptr) | Forward map: process FD → kernel sock |
| `sock_to_conn_id` | LRU Hash (64K) | `u64` (sock_ptr) | `conn_id {tgid, fd}` | Reverse map: kernel sock → process FD |
| `event_scratch` | Per-CPU Array (1) | `u32` | `data_event` | Scratch space to avoid 8KB BPF stack allocation |
| `active_data_args` | Hash (64K) | `pid_tgid` (u64) | `data_args {fd, buf}` | In-flight ingress syscall state |
| `active_connect_args` | Hash (4K) | `pid_tgid` (u64) | `connect_args {fd}` | In-flight `connect()` state |
| `active_accept_args` | Hash (4K) | `pid_tgid` (u64) | `accept_args {addr}` | In-flight `accept()` state |
| `active_ssl_read_args` | Hash (64K) | `pid_tgid` (u64) | `ssl_read_args {ssl_ptr, buf}` | In-flight `SSL_read()` state |
| `ssl_symaddrs` | Array (1) | `u32` | `ssl_symaddrs` | OpenSSL struct offsets (populated by Go at startup) |
| `stats_map` | Per-CPU Array (1) | `u32` | `stats` | Per-CPU packet counters |

## Protocol Detection Pipeline

Protocol classification happens in two stages:

### Stage 1: In-Kernel (BPF) — `protocol_inference.h`

Runs on every packet inside `emit_data_event()`:

1. **HTTP/2 preface check** — Matches the 24-byte magic string `PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`. Sets the sticky `http2_detected` flag on the connection.
2. **HTTP/2 frame validation** — Validates 9-byte frame header (length ≤ 16MB, type ≤ 0x09, stream-ID sanity checks per frame type).
3. **gRPC heuristic** — If a valid HTTP/2 HEADERS frame contains the substring `grpc` in its first 128 bytes, classify as gRPC.
4. **HTTP/1.x prefix** — Matches first 4 bytes against LE-encoded HTTP method signatures: `GET `, `POST`, `PUT `, `DELE`, `HEAD`, `PATC`, `OPTI`, `HTTP` (response).
5. **Sticky classification** — If current packet is `PROTO_UNKNOWN`, falls back to the connection's last-known protocol. Packets that remain `PROTO_UNKNOWN` with no prior classification are dropped silently.

### Stage 2: Userspace (Go) — `protocols/`

Full protocol parsing with header extraction, body reassembly, and stream multiplexing runs in userspace parsers (`http1/`, `http2/`, `grpc/`).

## In-Kernel Filtering

Traffic is filtered at three levels before reaching userspace:

1. **Port filter** (`should_trace_port()`) — Hardcoded exclusion of Kubernetes control-plane ports: `6443`, `8443`, `2379-2380`, `10250`, `10255-10256`, `9091`, `9099-9100`. Cached per-connection in `connection_filter_cache`.
2. **Health-check suppression** (`is_health_check()`) — Drops egress HTTP/1 `GET` requests to known health endpoints: `/health*`, `/readyz`, `/livez`, `/metrics`, `/debug*`, `/ping`.
3. **SSL deduplication** — When `conn_info.is_ssl` is set (by SSL uprobes), syscall kprobes skip that connection entirely, preventing duplicate events.

## FD→Sock Resolution

The connection tracker implements a two-tier resolution strategy:

1. **Fast path** — `pid_fd_to_sock` map lookup using `{tgid, fd}` key.
2. **Slow path (CO-RE fdtable walk)** — For connections established before probes attached: `task->files->fdt->fd[n]->private_data->sk`. Requires kernel ≥ 5.8 (BTF). Lazily populates both forward and reverse maps, and generates a `conn_info` from the socket's structural state (`skc_rcv_saddr`, `skc_daddr`, `skc_dport`, `skc_num`).

## Limitations

- **Payload cap**: `MAX_DATA_SIZE = 8192` bytes. Larger payloads are truncated with `FLAG_TRUNCATED`.
- **Vectored I/O**: Only `iov[0]` (first scatter-gather segment) is captured. For HTTP, headers are typically in the first iovec, so this is sufficient for protocol detection.
- **x86_64 only**: Syscall argument extraction assumes x86_64 syscall wrapper layout. ARM64 support requires different `pt_regs` field mappings.
- **IPv6**: IPv4-mapped IPv6 (`::ffff:x.x.x.x`) is supported, but pure IPv6 connections are silently ignored.
- **MSG_PEEK**: `recvfrom` and `recvmsg` handlers skip calls with `MSG_PEEK` flag to avoid double-capture.
- **Port filter**: The control-plane port exclusion list is hardcoded. A future version will use a `BPF_MAP_TYPE_HASH` for runtime configurability.
- **K8s watcher**: The userspace metadata enrichment watcher is currently a stub — IP-to-pod resolution is not yet functional.

## Testing Scenarios

| Scenario | What It Validates |
|---|---|
| **Multi-language HTTP servers** (Go `net/http`, Node.js `http`, Python Flask) | Different runtimes use different syscalls — Go uses `write`/`read`, Node.js uses `writev`/`readv`, Python uses `sendto`/`recvfrom`. All must be captured. |
| **HTTP/1.1 pipelining** | Multiple requests on a single connection must be FIFO-matched to responses. Verifies correlator queue behavior. |
| **HTTP/2 multiplexing** | Multiple concurrent streams on one connection must be independently matched by stream ID. |
| **gRPC unary + streaming** | gRPC uses HTTP/2 transport — verifies both in-kernel gRPC heuristic and userspace gRPC parser. |
| **HTTPS via OpenSSL** | SSL uprobes must intercept plaintext, mark connection as SSL, and suppress duplicate kprobe events. |
| **Pre-existing connections** | Connections established before KubeArmor starts must be resolved via CO-RE fdtable walk (slow path). |
| **High-throughput stress** | Ring buffer backpressure: verifies `dropped_packets` stats counter increments when ring buffer is full, rather than blocking the kernel. |
| **Connection churn** | Rapid connect/close cycles: verifies LRU map eviction doesn't cause stale `sock_ptr` references. |
| **Loopback + kube-system** | Filtering: verifies both BPF-side port filter and userspace namespace/loopback filters correctly suppress noise. |

## Current Results & Coverage

- **Syscall coverage**: 8 I/O probes (4 egress + 4 ingress) + 5 lifecycle probes + 1 tracepoint + 3 optional SSL uprobes = **17 probe points**.
- **Protocol coverage**: HTTP/1.x (all standard methods), HTTP/2 (preface + frame validation), gRPC (heuristic in-kernel, full parsing in userspace).
- **Per-CPU stats**: `total_packets`, `http1_packets`, `http2_packets`, `grpc_packets`, `filtered_packets`, `dropped_packets`, `parse_errors` — aggregated in userspace for observability.
- **Connection tracking**: Dual-map `{tgid,fd}↔sock_ptr` with CO-RE fallback ensures correct process attribution even for pre-existing or recycled connections.
