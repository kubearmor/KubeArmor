## Feature Request

**Short Description**

Implement capability-specific alert throttling at the eBPF/LSM kernel level to prevent perf buffer flooding and Go daemon CPU overhead.

**Is your feature request related to a problem? Please describe the use case.**

When a process triggers blocked capabilities in a loop, it floods the eBPF perf buffer and causes high CPU deserialization overhead in the Go daemon. While KubeArmor has a container-level rate limiter (`should_drop_alerts_per_container`), it does not have granular, capability-specific throttling. We want to throttle capability events by capability number and container ID inside the lsm/capable hook.

**Describe the solution you'd like**

1. Define a rate-limiting map (`kubearmor_capable_throttle` of type `BPF_MAP_TYPE_HASH`) keyed by container ID (`outer_key`) and capability number.
2. Implement a rate-limiting token-bucket algorithm directly in the `lsm/capable` hook (`enforce_cap`).
3. If a capability violation rate is exceeded, drop the user-space alert while maintaining the policy enforcement (-EPERM).

**Describe alternatives you've considered**

None. Capability-specific rate limiting must be done at the kernel level before ring buffer submission to avoid CPU deserialization overhead in user space.
