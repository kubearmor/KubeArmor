## Feature Request

**Short Description**

Utilize Cgroup Namespaces for host process identification to avoid collisions under configurations where host PID namespaces (`hostPID: true`) are active.

**Is your feature request related to a problem? Please describe the use case.**

In environments where host PID namespaces (`hostPID: true`) are active, mapping processes to containers can result in collisions. We need to use cgroup namespace IDs as well for host process identification to support enforcement on deployments.

**Describe the solution you'd like**

1. Update BPF helper structs in `common_types.h` and helper functions/macros in `shared.h`/`kernel_helpers.h` to track and extract cgroup namespace IDs (`cgroup_ns`).
2. Utilize host namespace bypass logic checking both `PROC_PID_INIT_INO` and `PROC_CGROUP_INIT_INO` to determine if a process belongs to the host environment.
3. Update BPF matching maps size from 8 bytes (`PidNS` + `MntNS`) to 12 bytes (`PidNS` + `MntNS` + `CgroupNS`) in the daemon code (enforcer, monitor, presets).
4. Update daemon discovery/handlers (containerd, docker, crio, nri, hooks) to resolve and register the cgroup namespace ID from `/proc/<pid>/ns/cgroup`.

**Describe alternatives you've considered**

None. Using cgroup namespace IDs is the standard Linux kernel way to uniquely identify container processes on the host.
