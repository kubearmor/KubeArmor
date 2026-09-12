# Limitation of OCI Hooks to Automate the Task of Applying AppArmor Profiles

## Precreate Hook

### Timing
The precreate hook is executed after the container configuration is generated but before the actual start of the container.

### Purpose
This hook is typically used to modify the container configuration or perform setup tasks that need to be done before the container starts. For example, you might use this hook to set up network interfaces or mount additional filesystems.

## AppArmor

AppArmor profiles are typically applied before a container is started. This is because AppArmor works by confining processes based on their profiles, and these profiles need to be loaded and enforced by the kernel when the process starts. Therefore, AppArmor profiles can only be applied during the Precreate stage.

## Limitation of Automating the Task of Applying AppArmor Profile of a Container

### Support for Non-Orchestrated Containers
During the OCI precreate hook, the container is not started yet, so there won’t be a container ID and container name available. Hence, it is not possible to apply an existing AppArmor profile for a container on that container name that has not yet been started during this stage.

### Process of Applying the Hook
1. Create a `KubeArmorPolicy` for the container you want to protect. This will lead to KubeArmor generating the template automatically.
2. Update this policy and add new policies as needed.
3. Whenever you run the container, the precreate hook is triggered. However, to apply this AppArmor profile, which is saved as `kubearmor_<container_name>`, the hook binary during this stage won’t receive the container ID and container name from the hook since this hook is run before the actual start of the container.

Hence, this process of automating the task of applying an AppArmor profile to a container is not possible.

### Example
Spec configuration received during the “precreate” hook can look like this, where there is a `process.apparmorProfile` field present which can be modified to change the AppArmor profile:

```json
Precreate Config:
{
  "ociVersion": "1.0.2-dev",
  "process": {
    "terminal": true,
    "user": {
      "uid": 0,
      "gid": 0,
      "umask": 18
    },
    "args": [
      "/bin/bash"
    ],
    "env": [
      "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
      "TERM=xterm",
      "container=oci",
      "HOME=/root",
      "HOSTNAME=2ce0d2ad61e6"
    ],
    "cwd": "/",
    "capabilities": {
      "bounding": [
        "CAP_CHOWN",
        "CAP_DAC_OVERRIDE",
        "CAP_FOWNER",
        "CAP_FSETID",
        "CAP_KILL",
        "CAP_NET_BIND_SERVICE",
        "CAP_SETFCAP",
        "CAP_SETGID",
        "CAP_SETPCAP",
        "CAP_SETUID",
        "CAP_SYS_CHROOT"
      ],
      "effective": [
        "CAP_CHOWN",
        "CAP_DAC_OVERRIDE",
        "CAP_FOWNER",
        "CAP_FSETID",
        "CAP_KILL",
        "CAP_NET_BIND_SERVICE",
        "CAP_SETFCAP",
        "CAP_SETGID",
        "CAP_SETPCAP",
        "CAP_SETUID",
        "CAP_SYS_CHROOT"
      ],
      "inheritable": [
        "CAP_CHOWN",
        "CAP_DAC_OVERRIDE",
        "CAP_FOWNER",
        "CAP_FSETID",
        "CAP_KILL",
        "CAP_NET_BIND_SERVICE",
        "CAP_SETFCAP",
        "CAP_SETGID",
        "CAP_SETPCAP",
        "CAP_SETUID",
        "CAP_SYS_CHROOT"
      ],
      "permitted": [
        "CAP_CHOWN",
        "CAP_DAC_OVERRIDE",
        "CAP_FOWNER",
        "CAP_FSETID",
        "CAP_KILL",
        "CAP_NET_BIND_SERVICE",
        "CAP_SETFCAP",
        "CAP_SETGID",
        "CAP_SETPCAP",
        "CAP_SETUID",
        "CAP_SYS_CHROOT"
      ]
    },
    "rlimits": [
      {
        "type": "RLIMIT_NOFILE",
        "hard": 1048576,
        "soft": 1048576
      },
      {
        "type": "RLIMIT_NPROC",
        "hard": 4194304,
        "soft": 4194304
      }
    ],
    "apparmorProfile": "containers-default-0.44.4",
    "oomScoreAdj": 0
  },
  "root": {
    "path": "/var/lib/containers/storage/overlay/ad6e6e9308e7cbef526baaf7b12bbbfb32b543f64ed8d1af5ec65de082c0129d/merged"
  },
  "hostname": "2ce0d2ad61e6",
  "mounts": [
    {
      "destination": "/proc",
      "type": "proc",
      "source": "proc",
      "options": [
        "nosuid",
        "noexec",
        "nodev"
      ]
    },
    {
      "destination": "/dev",
      "type": "tmpfs",
      "source": "tmpfs",
      "options": [
        "nosuid",
        "strictatime",
        "mode=755",
        "size=65536k"
      ]
    },
    {
      "destination": "/sys",
      "type": "sysfs",
      "source": "sysfs",
      "options": [
        "nosuid",
        "noexec",
        "nodev",
        "ro"
      ]
    },
    {
      "destination": "/dev/pts",
      "type": "devpts",
      "source": "devpts",
      "options": [
        "nosuid",
        "noexec",
        "newinstance",
        "ptmxmode=0666",
        "mode=0620",
        "gid=5"
      ]
    },
    {
      "destination": "/dev/mqueue",
      "type": "mqueue",
      "source": "mqueue",
      "options": [
        "nosuid",
        "noexec",
        "nodev"
      ]
    },
    {
      "destination": "/etc/resolv.conf",
      "type": "bind",
      "source": "/run/containers/storage/overlay-containers/2ce0d2ad61e6c6f318b83c01ca2f4f8fdef947a0345a5734c9fa885e5e963f0b/userdata/resolv.conf",
      "options": [
        "bind",
        "rprivate"
      ]
    },
    {
      "destination": "/etc/hosts",
      "type": "bind",
      "source": "/run/containers/storage/overlay-containers/2ce0d2ad61e6c6f318b83c01ca2f4f8fdef947a0345a5734c9fa885e5e963f0b/userdata/hosts",
      "options": [
        "bind",
        "rprivate"
      ]
    },
    {
      "destination": "/dev/shm",
      "type": "bind",
      "source": "/var/lib/containers/storage/overlay-containers/2ce0d2ad61e6c6f318b83c01ca2f4f8fdef947a0345a5734c9fa885e5e963f0b/userdata/shm",
      "options": [
        "bind",
        "rprivate"
      ]
    },
    {
      "destination": "/etc/hostname",
      "type": "bind",
      "source": "/run/containers/storage/overlay-containers/2ce0d2ad61e6c6f318b83c01ca2f4f8fdef947a0345a5734c9fa885e5e963f0b/userdata/hostname",
      "options": [
        "bind",
        "rprivate"
      ]
    },
    {
      "destination": "/run/.containerenv",
      "type": "bind",
      "source": "/run/containers/storage/overlay-containers/2ce0d2ad61e6c6f318b83c01ca2f4f8fdef947a0345a5734c9fa885e5e963f0b/userdata/.containerenv",
      "options": [
        "bind",
        "rprivate"
      ]
    },
    {
      "destination": "/sys/fs/cgroup",
      "type": "cgroup",
      "source": "cgroup",
      "options": [
        "rprivate",
        "nosuid",
        "noexec",
        "nodev",
        "relatime",
        "ro"
      ]
    }
  ],
  "hooks": {},
  "annotations": {
    "io.container.manager": "libpod",
    "io.kubernetes.cri-o.Created": "2024-07-29T11:36:40.51830451+05:30",
    "io.kubernetes.cri-o.TTY": "true",
    "io.podman.annotations.autoremove": "TRUE",
    "io.podman.annotations.init": "FALSE",
    "io.podman.annotations.privileged": "FALSE",
    "io.podman.annotations.publish-all": "FALSE",
    "org.opencontainers.image.base.digest": "",
    "org.opencontainers.image.base.name": "",
    "org.opencontainers.image.stopSignal": "15"
  },
  "linux": {
    "sysctl": {
      "net.ipv4.ping_group_range": "0 0"
    },
    "resources": {
      "pids": {
        "limit": 2048
      }
    },
    "cgroupsPath": "machine.slice:libpod:2ce0d2ad61e6c6f318b83c01ca2f4f8fdef947a0345a5734c9fa885e5e963f0b",
    "namespaces": [
      {
        "type": "pid"
      },
      {
        "type": "network",
        "path": "/run/netns/cni-b65c80f1-0f83-c67e-972b-006aca1e4dc6"
      },
      {
        "type": "ipc"
      },
      {
        "type": "uts"
      },
      {
        "type": "mount"
      },
      {
        "type": "cgroup"
      }
    ],
    "seccomp": {
      "defaultAction": "SCMP_ACT_ERRNO",
      "defaultErrnoRet": 38,
      "architectures": [
        "SCMP_ARCH_X86_64",
        "SCMP_ARCH_X86",
        "SCMP_ARCH_X32"
      ],
      "syscalls": [
        {
          "names": [
            "bdflush",
            "io_pgetevents",
            "kexec_file_load",
            "kexec_load",
            "migrate_pages",
            "move_pages",
            "nfsservctl",
            "nice",
            "oldfstat",
            "oldlstat",
            "oldolduname",
            "oldstat",
            "olduname",
            "pciconfig_iobase",
            "pciconfig_read",
            "pciconfig_write",
            "sgetmask",
            "ssetmask",
            "swapcontext",
            "swapoff",
            "swapon",
            "sysfs",
            "uselib",
            "userfaultfd",
            "ustat",
            "vm86",
            "vm86old",
            "vmsplice"
          ],
          "action": "SCMP_ACT_ERRNO",
          "errnoRet": 1
        },
        {
          "names": [
            "_llseek",
            "_newselect",
            "accept",
            "accept4",
            "access",
            "adjtimex",
            "alarm",
            "bind",
            "brk",
            "capget",
            "capset",
            "chdir",
            "chmod",
            "chown",
            "chown32",
            "clock_adjtime",
            "clock_adjtime64",
            "clock_getres",
            "clock_getres_time64",
            "clock_gettime",
            "clock_gettime64",
            "clock_nanosleep",
            "clock_nanosleep_time64",
            "clone",
            "clone3",
            "close",
            "close_range",
            "connect",
            "copy_file_range",
            "creat",
            "dup",
            "dup2",
            "dup3",
            "epoll_create",
            "epoll_create1",
            "epoll_ctl",
            "epoll_ctl_old",
            "epoll_pwait",
            "epoll_pwait2",
            "epoll_wait",
            "epoll_wait_old",
            "eventfd",
            "eventfd2",
            "execve",
            "execveat",
            "exit",
            "exit_group",
            "faccessat",
            "faccessat2",
            "fadvise64",
            "fadvise64_64",
            "fallocate",
            "fanotify_mark",
            "fchdir",
            "fchmod",
            "fchmodat",
            "fchown",
            "fchown32",
            "fchownat",
            "fcntl",
            "fcntl64",
            "fdatasync",
            "fgetxattr",
            "flistxattr",
            "flock",
            "fork",
            "fremovexattr",
            "fsconfig",
            "fsetxattr",
            "fsmount",
            "fsopen",
            "fspick",
            "fstat",
            "fstat64",
            "fstatat64",
            "fstatfs",
            "fstatfs64",
            "fsync",
            "ftruncate",
            "ftruncate64",
            "futex",
            "futex_time64",
            "futimesat",
            "get_robust_list",
            "get_thread_area",
            "getcpu",
            "getcwd",
            "getdents",
            "getdents64",
            "getegid",
            "getegid32",
            "geteuid",
            "geteuid32",
            "getgid",
            "getgid32",
            "getgroups",
            "getgroups32",
            "getitimer",
            "get_mempolicy",
            "getpeername",
            "getpgid",
            "getpgrp",
            "getpid",
            "getppid",
            "getpriority",
            "getrandom",
            "getresgid",
            "getresgid32",
            "getresuid",
            "getresuid32",
            "getrlimit",
            "getrusage",
            "getsid",
            "getsockname",
            "getsockopt",
            "gettid",
            "gettimeofday",
            "getuid",
            "getuid32",
            "getxattr",
            "inotify_add_watch",
            "inotify_init",
            "inotify_init1",
            "inotify_rm_watch",
            "io_cancel",
            "io_destroy",
            "io_getevents",
            "io_setup",
            "io_submit",
            "ioctl",
            "ioprio_get",
            "ioprio_set",
            "ipc",
            "keyctl",
            "kill",
            "lchown",
            "lchown32",
            "lgetxattr",
            "link",
            "linkat",
            "listen",
            "listxattr",
            "llistxattr",
            "lremovexattr",
            "lseek",
            "lsetxattr",
            "lstat",
            "lstat64",
            "madvise",
            "mbind",
            "memfd_create",
            "memfd_secret",
            "mincore",
            "mkdir",
            "mkdirat",
            "mknod",
            "mknodat",
            "mlock",
            "mlock2",
            "mlockall",
            "mmap",
            "mmap2",
            "mount",
            "move_mount",
            "mprotect",
            "mq_getsetattr",
            "mq_notify",
            "mq_open",
            "mq_timedreceive",
            "mq_timedreceive_time64",
            "mq_timedsend",
            "mq_timedsend_time64",
            "mq_unlink",
            "mremap",
            "msgctl",
            "msgget",
            "msgrcv",
            "msgsnd",
            "msync",
            "munlock",
            "munlockall",
            "munmap",
            "name_to_handle_at",
            "nanosleep",
            "newfstatat",
            "open",
            "openat",
            "openat2",
            "open_tree",
            "pause",
            "pidfd_getfd",
            "pidfd_open",
            "pidfd_send_signal",
            "pipe",
            "pipe2",
            "pivot_root",
            "pkey_alloc",
            "pkey_free",
            "pkey_mprotect",
            "poll",
            "ppoll",
            "ppoll_time64",
            "prctl",
            "pread64",
            "preadv",
            "preadv2",
            "prlimit64",
            "pselect6",
            "pselect6_time64",
            "pwrite64",
            "pwritev",
            "pwritev2",
            "read",
            "readahead",
            "readdir",
            "readlink",
            "readlinkat",
            "readv",
            "reboot",
            "recv",
            "recvfrom",
            "recvmmsg",
            "recvmmsg_time64",
            "recvmsg",
            "remap_file_pages",
            "removexattr",
            "rename",
            "renameat",
            "renameat2",
            "restart_syscall",
            "rmdir",
            "rseq",
            "rt_sigaction",
            "rt_sigpending",
            "rt_sigprocmask",
            "rt_sigqueueinfo",
            "rt_sigreturn",
            "rt_sigsuspend",
            "rt_sigtimedwait",
            "rt_sigtimedwait_time64",
            "rt_tgsigqueueinfo",
            "sched_get_priority_max",
            "sched_get_priority_min",
            "sched_getaffinity",
            "sched_getattr",
            "sched_getparam",
            "sched_getscheduler",
            "sched_rr_get_interval",
            "sched_rr_get_interval_time64",
            "sched_setaffinity",
            "sched_setattr",
            "sched_setparam",
            "sched_setscheduler",
            "sched_yield",
            "seccomp",
            "select",
            "semctl",
            "semget",
            "semop",
            "semtimedop",
            "semtimedop_time64",
            "send",
            "sendfile",
            "sendfile64",
            "sendmmsg",
            "sendmsg",
            "sendto",
            "setns",
            "set_mempolicy",
            "set_robust_list",
            "set_thread_area",
            "set_tid_address",
            "setfsgid",
            "setfsgid32",
            "setfsuid",
            "setfsuid32",
            "setgid",
            "setgid32",
            "setgroups",
            "setgroups32",
            "setitimer",
            "setpgid",
            "setpriority",
            "setregid",
            "setregid32",
            "setresgid",
            "setresgid32",
            "setresuid",
            "setresuid32",
            "setreuid",
            "setreuid32",
            "setrlimit",
            "setsid",
            "setsockopt",
            "setuid",
            "setuid32",
            "setxattr",
            "shmat",
            "shmctl",
            "shmdt",
            "shmget",
            "shutdown",
            "sigaltstack",
            "signalfd",
            "signalfd4",
            "sigreturn",
            "socketcall",
            "socketpair",
            "splice",
            "stat",
            "stat64",
            "statfs",
            "statfs64",
            "statx",
            "symlink",
            "symlinkat",
            "sync",
            "sync_file_range",
            "syncfs",
            "sysinfo",
            "syslog",
            "tee",
            "tgkill",
            "time",
            "timer_create",
            "timer_delete",
            "timer_getoverrun",
            "timer_gettime",
            "timer_gettime64",
            "timer_settime",
            "timer_settime64",
            "timerfd_create",
            "timerfd_gettime",
            "timerfd_gettime64",
            "timerfd_settime",
            "timerfd_settime64",
            "times",
            "tkill",
            "truncate",
            "truncate64",
            "ugetrlimit",
            "umask",
            "umount",
            "umount2",
            "uname",
            "unlink",
            "unlinkat",
            "unshare",
            "utime",
            "utimensat",
            "utimensat_time64",
            "utimes",
            "vfork",
            "wait4",
            "waitid",
            "waitpid",
            "write",
            "writev"
          ],
          "action": "SCMP_ACT_ALLOW"
        },
        {
          "names": [
            "personality"
          ],
          "action": "SCMP_ACT_ALLOW",
          "args": [
            {
              "index": 0,
              "value": 0,
              "op": "SCMP_CMP_EQ"
            }
          ]
        },
        {
          "names": [
            "personality"
          ],
          "action": "SCMP_ACT_ALLOW",
          "args": [
            {
              "index": 0,
              "value": 8,
              "op": "SCMP_CMP_EQ"
            }
          ]
        },
        {
          "names": [
            "personality"
          ],
          "action": "SCMP_ACT_ALLOW",
          "args": [
            {
              "index": 0,
              "value": 131072,
              "op": "SCMP_CMP_EQ"
            }
          ]
        },
        {
          "names": [
            "personality"
          ],
          "action": "SCMP_ACT_ALLOW",
          "args": [
            {
              "index": 0,
              "value": 131080,
              "op": "SCMP_CMP_EQ"
            }
          ]
        },
        {
          "names": [
            "personality"
          ],
          "action": "SCMP_ACT_ALLOW",
          "args": [
            {
              "index": 0,
              "value": 4294967295,
              "op": "SCMP_CMP_EQ"
            }
          ]
        },
        {
          "names": [
            "arch_prctl"
          ],
          "action": "SCMP_ACT_ALLOW"
        },
        {
          "names": [
            "modify_ldt"
          ],
          "action": "SCMP_ACT_ALLOW"
        },
        {
          "names": [
            "open_by_handle_at"
          ],
          "action": "SCMP_ACT_ERRNO",
          "errnoRet": 1
        },
        {
          "names": [
            "bpf",
            "fanotify_init",
            "lookup_dcookie",
            "perf_event_open",
            "quotactl",
            "setdomainname",
            "sethostname",
            "setns"
          ],
          "action": "SCMP_ACT_ERRNO",
          "errnoRet": 1
        },
        {
          "names": [
            "chroot"
          ],
          "action": "SCMP_ACT_ALLOW"
        },
        {
          "names": [
            "delete_module",
            "init_module",
            "finit_module",
            "query_module"
          ],
          "action": "SCMP_ACT_ERRNO",
          "errnoRet": 1
        },
        {
          "names": [
            "acct"
          ],
          "action": "SCMP_ACT_ERRNO",
          "errnoRet": 1
        },
        {
          "names": [
            "kcmp",
            "process_madvise",
            "process_vm_readv",
            "process_vm_writev",
            "ptrace"
          ],
          "action": "SCMP_ACT_ERRNO",
          "errnoRet": 1
        },
        {
          "names": [
            "iopl",
            "ioperm"
          ],
          "action": "SCMP_ACT_ERRNO",
          "errnoRet": 1
        },
        {
          "names": [
            "settimeofday",
            "stime",
            "clock_settime",
            "clock_settime64"
          ],
          "action": "SCMP_ACT_ERRNO",
          "errnoRet": 1
        },
        {
          "names": [
            "vhangup"
          ],
          "action": "SCMP_ACT_ERRNO",
          "errnoRet": 1
        },
        {
          "names": [
            "socket"
          ],
          "action": "SCMP_ACT_ERRNO",
          "errnoRet": 22,
          "args": [
            {
              "index": 0,
              "value": 16,
              "op": "SCMP_CMP_EQ"
            },
            {
              "index": 2,
              "value": 9,
              "op": "SCMP_CMP_EQ"
            }
          ]
        },
        {
          "names": [
            "socket"
          ],
          "action": "SCMP_ACT_ALLOW",
          "args": [
            {
              "index": 2,
              "value": 9,
              "op": "SCMP_CMP_NE"
            }
          ]
        },
        {
          "names": [
            "socket"
          ],
          "action": "SCMP_ACT_ALLOW",
          "args": [
            {
              "index": 0,
              "value": 16,
              "op": "SCMP_CMP_NE"
            }
          ]
        },
        {
          "names": [
            "socket"
          ],
          "action": "SCMP_ACT_ALLOW",
          "args": [
            {
              "index": 2,
              "value": 9,
              "op": "SCMP_CMP_NE"
            }
          ]
        }
      ]
    },
    "maskedPaths": [
      "/proc/acpi",
      "/proc/kcore",
      "/proc/keys",
      "/proc/latency_stats",
      "/proc/timer_list",
      "/proc/timer_stats",
      "/proc/sched_debug",
      "/proc/scsi",
      "/sys/firmware",
      "/sys/fs/selinux",
      "/sys/dev/block"
    ],
    "readonlyPaths": [
      "/proc/asound",
      "/proc/bus",
      "/proc/fs",
      "/proc/irq",
      "/proc/sys",
      "/proc/sysrq-trigger"
    ]
  }
}
