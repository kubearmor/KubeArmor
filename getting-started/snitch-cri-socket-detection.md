# Snitch: CRI socket detection and runtime inference

## Overview

`snitch` is a CLI utility used by KubeArmor Operator to detect node-related information, including the container runtime and the CRI socket.

This page explains how `snitch` selects a CRI socket and how the runtime is inferred from the detected socket path.

## Prerequisites

- Access to a Kubernetes node filesystem (for example, via a privileged DaemonSet) so that runtime socket paths are visible.

## How socket selection works

`snitch` detects the node runtime by looking for known CRI socket paths and selecting the socket that exists on the node.

### Provide an explicit socket path

Use `--socket-file` to force `snitch` to use a specific CRI socket path.

```bash
snitch --socket-file /var/run/containerd/containerd.sock
```

The socket path must be an absolute path (must start with `/`).

## How runtime is inferred from the socket path

When `snitch` has a socket path, it derives the runtime name from the socket location:

| Socket path pattern | Inferred runtime |
| --- | --- |
| `.../docker.sock` | `docker` |
| `.../containerd.sock` | `containerd` |
| `.../crio.sock` | `cri-o` |

If the socket path does not match a known pattern, the runtime falls back to `containerd`.

## Troubleshooting

### Socket path is rejected

If `--socket-file` is set to a relative path (does not start with `/`), runtime detection returns `NA`.

### Runtime is detected, but runtime client fails

If the runtime client fails to initialize, verify that the socket path matches the runtime you expect to use.
