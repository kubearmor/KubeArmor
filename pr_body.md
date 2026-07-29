**Purpose of PR?**:

This PR utilizes cgroup namespaces for host process identification in the BPF Enforcer. It updates the BPF helpers, maps, enforcers, and daemon handlers to include cgroup namespace ID tracking alongside PID and mount namespace IDs. This resolves process identification collisions under `hostPID: true` configurations.

Fixes #2781

**Does this PR introduce a breaking change?**

No.

**If the changes in this PR are manually verified, list down the scenarios covered:**:

1. Verification of compilation: Built BPF programs and Go daemon successfully using `go generate ./...`.
2. Execution of unit tests: All package unit tests passed with `GOOS=linux go test -exec=/usr/bin/true ./...`.

**Additional information for reviewer?** :

Key modifications:
- Track `cgroup_ns` field in `outer_key` struct in `common_types.h`, `shared.h`, and `kernel_helpers.h`.
- Set map key size to 12 bytes for container maps (`kubearmor_containers`, `kubearmor_alert_throttle`, `kubearmor_visibility`, and preset maps).
- Update daemon handlers (containerd, docker, crio, nri, hook handlers) to read `/proc/<pid>/ns/cgroup` and register the `CgroupNS` parameter.

**Checklist:**
- [x] Bug fix. Fixes #2781
- [x] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] This change requires a documentation update
- [x] PR Title follows the Palace convention of `<type>(<scope>): <subject>`
- [x] Commit has unit tests
- [x] Commit has integration tests
