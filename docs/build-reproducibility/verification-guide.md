# Verification Guide

This guide shows how to verify that a published KubeArmor release binary matches one you
build yourself from the source commit.

## Prerequisites

- Linux (x86_64)
- Git, Make
- Go — the exact version in `KubeArmor/go.mod` (see [build-environment.md](build-environment.md))

## Step 1: Check out the exact release tag (clean)

```bash
git clone https://github.com/kubearmor/KubeArmor.git
cd KubeArmor
git checkout v1.0.0      # the release tag you are verifying
git status               # MUST be clean — uncommitted changes change the binary
```

## Step 2: Verify your environment

```bash
bash scripts/verify-reproducible-build.sh --check-env
```

A wrong Go version is the most common cause of a checksum mismatch — fix any reported issues.

## Step 3: Build reproducibly

```bash
make -C KubeArmor build-reproducible
```

This produces `KubeArmor/kubearmor` and is equivalent to what the release pipeline
(`KubeArmor/.goreleaser.yaml`) runs:

```bash
SOURCE_DATE_EPOCH=$(git log -1 --format=%ct) CGO_ENABLED=0 go build \
  -trimpath \
  -mod=readonly \
  -ldflags "-buildid= \
    -X github.com/kubearmor/KubeArmor/KubeArmor/buildinfo.GitSummary=$(git describe --tags --dirty --always) \
    -X github.com/kubearmor/KubeArmor/KubeArmor/buildinfo.BuildDate=$(git log -1 --format=%ct)" \
  -o KubeArmor/kubearmor .
```

## Step 4: Compute and compare the checksum

```bash
sha256sum KubeArmor/kubearmor
```

Each release publishes a checksums file as a GitHub release asset
(`kubearmor_<version>_<arch>_checksums.txt`). Download it and compare:

```bash
curl -fsSL https://github.com/kubearmor/KubeArmor/releases/download/v1.0.0/kubearmor_v1.0.0_amd64_checksums.txt \
  -o checksums.txt
grep kubearmor checksums.txt
```

If your SHA-256 matches the published value, the release is authentic.

## Automated verification

The script builds twice and confirms the two binaries are identical (proving the build is
deterministic). It delegates the build to `make build-reproducible`, so there is a single
source of truth for the flags.

```bash
bash scripts/verify-reproducible-build.sh          # verify current HEAD
bash scripts/verify-reproducible-build.sh v1.0.0   # check out a tag first, then verify
```

Exit code 0 means the builds matched; exit code 1 means they differed.

## Troubleshooting

### Checksums do not match

1. **Dirty working tree** — run `git status`. Any uncommitted change appends `-dirty` to the
   version string and sets `vcs.modified=true`, both of which change the binary.
   Restore a clean tree with `git checkout -- .`.
2. **Wrong Go version** — compare `go version` with `grep '^go ' KubeArmor/go.mod`. They must
   match exactly, including the patch version.
3. **Wrong commit** — confirm `git log -1 --oneline` matches the release tag.
4. **Non-Linux/amd64 host** — only `linux/amd64` is validated against releases.
5. **CGO enabled** — ensure `CGO_ENABLED=0`; a C compiler in `PATH` can be picked up.

### Build fails

- The reproducible target uses `-mod=readonly`; if it complains about `go.sum`, your tree
  is not a clean checkout of the tag.
- Ensure the committed `*.pb.go` and BPF `*.o` files are present (they ship in the repo).

### I used `make build` and it does not match

`make build` is the non-deterministic developer build (it uses `govvv`, which embeds the
current time). Always use `make build-reproducible` for verification.
