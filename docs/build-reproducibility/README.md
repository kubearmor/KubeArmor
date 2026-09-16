# Build Reproducibility

KubeArmor supports reproducible builds: anyone can rebuild a released `kubearmor` binary
from its source commit and obtain a **byte-for-byte identical** result.

## What Is a Reproducible Build?

A reproducible build produces identical output when given the same source code, build
environment, and build flags — regardless of who runs it, where, or when. This means:

- You can independently rebuild a KubeArmor release and get an identical binary.
- A checksum mismatch signals that either your environment differs or the binary was tampered with.

## Why It Matters

KubeArmor is a kernel-level security tool. Trusting the binary is not optional.
Reproducible builds provide:

- **Verifiable supply chain**: Confirm a release binary came from published source code.
- **Tamper detection**: Any modification to the binary after build produces a different checksum.
- **Supply-chain compliance**: Aligns with SLSA and OpenSSF best practices.

## How KubeArmor Builds Releases

Released `kubearmor` binaries are produced by **GoReleaser** (`KubeArmor/.goreleaser.yaml`),
invoked from the release CI workflow. The GoReleaser config and the `make build-reproducible`
target use the same deterministic settings, so:

> Running `make build-reproducible` on a clean checkout of a release tag reproduces the
> published release binary byte-for-byte. *(Verified: the Makefile output matches the
> GoReleaser build output exactly.)*

### What makes the build deterministic

| Setting | Effect |
|---|---|
| `mod_timestamp` / `SOURCE_DATE_EPOCH` = commit time | No wall-clock time embedded |
| `-trimpath` | Strips local filesystem paths (GOPATH, checkout dir) |
| `-buildid=` | Removes the random build ID the Go linker would embed |
| `-X buildinfo.GitSummary` = `git describe --tags --dirty --always` | Deterministic version string |
| `-X buildinfo.BuildDate` = commit timestamp | Deterministic build date |
| `GitBranch` intentionally **not** embedded | Branch is not a deterministic property of a commit |
| Committed BPF `.o` and protobuf `.pb.go` used as-is | No regeneration → no `clang`/`protoc` variability |

> Note: the previous GoReleaser `ldflags` targeted `main.*` symbols that do not exist, so
> they were silent no-ops (released binaries had empty build info). They now correctly target
> the `buildinfo` package, which both fixes that latent bug and makes the values deterministic.

## Quick Start

### Verify a release binary

```bash
git checkout v1.0.0                       # the exact release tag, clean tree
make -C KubeArmor build-reproducible      # produces KubeArmor/kubearmor
sha256sum KubeArmor/kubearmor             # compare with the release checksums.txt asset
```

### Run the verification script

```bash
bash scripts/verify-reproducible-build.sh            # double-build the current HEAD and compare
bash scripts/verify-reproducible-build.sh v1.0.0     # check out a tag first, then verify
bash scripts/verify-reproducible-build.sh --check-env # validate the environment only
```

## Documentation

| Document | Description |
|---|---|
| [Build Environment](build-environment.md) | Required tools, versions, and what inputs matter |
| [Verification Guide](verification-guide.md) | Step-by-step verification of a release |

## `make build` vs `make build-reproducible`

`make build` is the **developer** build. It uses `govvv` (which embeds the current wall-clock
time) and runs `go mod tidy`, so it is intentionally **not** reproducible. Use
`make build-reproducible` whenever you need a deterministic, verifiable binary.

## Known Limitations

- **Architecture/OS**: Reproducibility is validated for `linux/amd64`. Other targets are
  not currently covered.
- **BPF/protobuf regeneration**: The reproducible build uses the committed `*.o` and `*.pb.go`
  artifacts. *Regenerating* them from source depends on the exact `clang`/`llvm`/`protoc`
  versions and is out of scope for this workflow.
- **Go toolchain**: The exact Go version from `KubeArmor/go.mod` must be used; different patch
  releases of Go can change code generation.
