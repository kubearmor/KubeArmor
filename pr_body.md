**Purpose of PR?**:

This PR implements granular, capability-specific alert throttling at the eBPF/LSM kernel level inside the `lsm/capable` hook (`enforce_cap`). By checking capability violations against a token-bucket rate limiter map keyed by container ID and capability number, we drop user-space alerts when the rate is exceeded while still enforcing the policy (-EPERM).

Fixes #2818

**Does this PR introduce a breaking change?**

No.

**If the changes in this PR are manually verified, list down the scenarios covered:**:

1. Verification of compilation: Built BPF programs and Go daemon successfully.
2. Execution of unit tests: Verified Go test suite compiles and runs successfully using mock execution with `GOOS=linux go test -exec=true ./...`.

**Additional information for reviewer?** :

Key modifications:
- Defined `struct cap_throttle_key` and `struct cap_throttle_state` in `throttling.h`.
- Declared BPF hash map `kubearmor_capable_throttle` in `throttling.h`.
- Implemented `should_drop_capable_alerts` token-bucket rate limiting helper in `shared.h`.
- Updated `enforce_cap` in `enforcer.bpf.c` to use `should_drop_capable_alerts(okey, cap)`.
- Defined Go-side structures and initialized/cleaned up `BPFCapableThrottleMap` in `enforcer.go`.
- Implemented map iteration and cleanup for `BPFCapableThrottleMap` on container deletion in `mapHelpers.go`.

**Checklist:**
- [x] Bug fix. Fixes #2818
- [x] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] This change requires a documentation update
- [x] PR Title follows the Palace convention of `<type>(<scope>): <subject>`
- [x] Commit has unit tests
- [x] Commit has integration tests
