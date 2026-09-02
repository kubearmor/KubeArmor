# Build Environment Requirements

To reproduce a KubeArmor binary that is byte-for-byte identical to a published release,
your environment must match the following specification.

## Operating System

| Requirement | Value |
|---|---|
| OS | Linux |
| Architecture | x86_64 / amd64 |
| Distribution | Ubuntu 22.04 or compatible |

Reproducibility is validated for `linux/amd64` (the platform the release CI uses).
macOS/Windows and other architectures produce different binaries.

## Required Tools

| Tool | Version | Notes |
|---|---|---|
| Go | Exactly the `go` directive in `KubeArmor/go.mod` | Patch releases can change codegen |
| Git | Any recent version | Provides the commit timestamp and version string |
| Make | Any recent version | Drives `make build-reproducible` |

Check the required Go version for a given commit:

```bash
grep '^go ' KubeArmor/go.mod
```

Install the exact version with `go install golang.org/dl/go<VERSION>@latest && go<VERSION> download`.

## Build Inputs That Must Match

All of the following determine the binary. They must be identical for checksums to match.

| Input | How it is fixed |
|---|---|
| Source tree | Clean `git checkout` of the target tag (no local modifications) |
| Go version | Exact version from `go.mod` |
| Version string | `git describe --tags --dirty --always` — identical on a clean tag checkout |
| Build timestamp | `SOURCE_DATE_EPOCH` = `git log -1 --format=%ct` (commit time) |
| Build flags | `-trimpath -buildid=` (applied by `make build-reproducible`) |
| CGO | Disabled (`CGO_ENABLED=0`) |
| Committed artifacts | `*.pb.go` and BPF `*.o` files as committed in the tree |

> A **clean** working tree matters: `git describe --dirty` appends `-dirty` and Go's VCS
> stamp records `vcs.modified=true` when there are uncommitted changes, both of which change
> the binary. Run `git status` and ensure the tree is clean before building.

## Inputs That Do NOT Affect the Output

- Hostname and username of the build machine.
- Current wall-clock time (the build uses the commit time instead).
- Directory where the repository is checked out (removed by `-trimpath`).
- `GOPATH` / `GOMODCACHE` locations (removed by `-trimpath`).
- Branch name (intentionally not embedded).

## Verifying Your Environment

```bash
bash scripts/verify-reproducible-build.sh --check-env
```

This checks the required tools, the Go version against `go.mod`, the architecture,
`CGO_ENABLED`, and whether the working tree is clean.

## BPF Objects and Protobuf — Important

KubeArmor embeds compiled eBPF objects (`KubeArmor/**/*_bpfel.o`, `*_bpfeb.o`) and generated
gRPC/protobuf code (`protobuf/*.pb.go`). **These artifacts are committed to the repository.**

The reproducible build (and the GoReleaser release build) compile against these committed
artifacts and do **not** regenerate them. As a result:

- The Go binary is fully reproducible from a checkout using only the Go toolchain — no
  `clang`, `llvm`, or `protoc` is required.
- *Regenerating* the BPF objects or `.pb.go` files from their C/`.proto` sources depends on
  the exact `clang`/`llvm`/`protoc` versions and is **out of scope** for this workflow.
