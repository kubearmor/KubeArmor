# Configurable Port Filter

The API Observer uses a BPF-based port exclusion map to filter out traffic on ports that should not be traced. 

## How It Works

```
┌─────────────┐      ┌──────────────────────┐      ┌───────────────┐
│  BPF Probe  │─────▶│  port_exclusion_map  │─────▶│  Drop / Pass  │
│  (kprobe)   │      │  (BPF_MAP_TYPE_HASH) │      │  Decision     │
└─────────────┘      └──────────────────────┘      └───────────────┘
                              ▲
                              │ Populated at startup
                     ┌────────┴─────────┐
                     │  Go Userspace    │
                     │  (apiObserver)   │
                     └──────────────────┘
```

At startup, the API Observer populates a BPF hash map (`port_exclusion_map`) with ports that should be excluded from tracing. The BPF-side `should_trace_port()` function performs a single map lookup — if the port is found, traffic is dropped at the kernel level before any data is copied to userspace.

### Key advantages over the old hardcoded switch:
- **No recompilation needed** — ports are configured via CLI flag, env var, or config file
- **Zero-copy kernel-level filtering** — excluded traffic never reaches userspace
- **Additive** — user-specified ports are added on top of the built-in defaults

## Default Excluded Ports

The following Kubernetes infrastructure ports are excluded by default:

| Port  | Service               |
|-------|-----------------------|
| 6443  | kube-apiserver        |
| 2379  | etcd client           |
| 2380  | etcd peer             |
| 10250 | kubelet API           |
| 10255 | kubelet read-only     |
| 10256 | kube-proxy health     |
| 9091  | Prometheus pushgateway|
| 9099  | Calico felix          |
| 9100  | node-exporter         |

## Configuration

### CLI Flag

```bash
kubearmor --enableAPIObserver --apiObserverExcludedPorts="8080,9090,3000"
```

### Environment Variable

```bash
export APIOBSERVEREXCLUDEDPORTS="8080,9090,3000"
kubearmor --enableAPIObserver
```

### Config File (`kubearmor.yaml`)

```yaml
enableAPIObserver: true
apiObserverExcludedPorts: "8080,9090,3000"
```

### Helm Values (KubeArmor Operator)

```yaml
kubearmor:
  args:
    - --enableAPIObserver
    - --apiObserverExcludedPorts=8080,9090,3000
```

## Format

- Comma-separated list of port numbers (1–65535)
- Whitespace around ports is trimmed
- Invalid entries are logged as warnings and skipped
- Empty string means no additional ports (only defaults apply)

## Verification

On startup, KubeArmor logs the total count of excluded ports:

```
Port exclusion map populated: 12 ports excluded
```

This includes both the 9 default ports and any user-specified additions.

## Architecture

### BPF Side

```c
// common/maps.h
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 64);
  __type(key, __u16);    // port number
  __type(value, __u8);   // 1 = excluded
} port_exclusion_map SEC(".maps");

// filter_helpers.h
static __always_inline int should_trace_port(u16 port) {
  u8 *excluded = bpf_map_lookup_elem(&port_exclusion_map, &port);
  return excluded == NULL;  // trace if NOT in exclusion map
}
```

### Go Side

```go
// config/config.go
APIObserverExcludedPorts string  // "8080,9090,3000"

// apiObserver.go
func (ao *APIObserver) populatePortExclusions() {
    // 1. Insert defaultExcludedPorts (K8s infra)
    // 2. Parse and insert GlobalCfg.APIObserverExcludedPorts
}
```

## Notes

- The map has a max capacity of 64 entries (default 9 + up to 55 user-specified)
- Port `8443` was removed from the default exclusion list because it is commonly used by application HTTPS servers (e.g., nginx, Flask with TLS)
- Both source and destination ports are checked — if either endpoint is excluded, the entire connection is dropped
