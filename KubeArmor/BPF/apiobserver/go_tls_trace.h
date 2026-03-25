/* SPDX-License-Identifier: GPL-2.0
 * Copyright 2026 Authors of KubeArmor
 *
 * go_tls_trace.h — BPF uprobes for Go crypto/tls.(*Conn) Read/Write.
 *
 * Captures decrypted plaintext from Go applications that use the standard
 * library's TLS implementation (HTTPS servers, gRPC-TLS, etc).
 *
 * IMPORTANT: uretprobes CANNOT be used for Go programs because goroutine
 * stack relocation corrupts the trampoline return address. Instead, we use
 * the kubeshark approach: disassemble the function body to find all `ret`
 * instructions, and attach regular uprobes at each ret offset (the "_ex"
 * probes). See go_tls_offsets.go for the disassembly code.
 *
 * Architecture support: Both amd64 and arm64 are supported via
 * arch-specific register access macros.
 *
 * Data flow:
 *   1. Entry uprobe (go_tls_write / go_tls_read):
 *      - Saves {buffer_ptr, buffer_len, conn_ptr} in ks_go_write/read_context
 *      - Keyed by (pid << 32 | goroutine_addr)
 *
 *   2. Inner syscall tracepoints (ks_fd_tracepoints.h):
 *      - sys_enter_write captures FD → ks_go_kernel_write_context[pid_tgid]
 *
 *   3. TCP kprobes (ks_tcp_kprobes.h):
 *      - tcp_sendmsg reads sock addr → ks_go_user_kernel_write_context[(pid<<32|fd)]
 *
 *   4. Ret uprobe (go_tls_write_ex / go_tls_read_ex):
 *      - Reads return value from registers
 *      - Looks up address info from ks_go_user_kernel context
 *      - Emits chunk via ks_output_ssl_chunk → ks_chunks_buffer perf
 *
 * Ported from kubeshark/tracer bpf/go_uprobes.c (GPL-3.0)
 */

#pragma once

#include "common/macros.h"
#include "common/maps.h"
#include "common/structs.h"
#include "ks_ssl_common.h"

/* ---- Architecture-specific Go register ABI (ABIInternal, Go >= 1.17) ---- */

/*
 * Go ABIInternal register mapping:
 *   https://go.googlesource.com/go/+/refs/heads/master/src/cmd/compile/abi-internal.md
 *
 * amd64:
 *   R1=AX, R2=CX, R3=DX, R4=BX, R5=BP, R6=SI, R7=DI
 *   SP=SP, GP(goroutine)=R14
 *
 * arm64:
 *   R1=X0, R2=X1, R3=X2, R4=X3, R5=X4, R6=X5, R7=X6
 *   SP=SP, GP(goroutine)=X28
 *
 * For crypto/tls.(*Conn).Write(b []byte) (int, error):
 *   Entry: R1=receiver(*Conn), R4=b.ptr, R2=b.len
 *   Return: R1=n(int), R6=err.type, R7=err.ptr
 *
 * For crypto/tls.(*Conn).Read(b []byte) (int, error):
 *   Entry: R1=receiver(*Conn), R4=b.ptr, R2=b.len
 *   Return: R1=n(int), R6=err.type, R7=err.ptr
 */

#if defined(__TARGET_ARCH_x86) || defined(__x86_64__)

#define GO_TLS_PARAM_RECEIVER(ctx) ((u64)(ctx)->ax)
#define GO_TLS_PARAM_BUF_PTR(ctx)  ((u64)(ctx)->bx)
#define GO_TLS_PARAM_BUF_LEN(ctx)  ((u64)(ctx)->cx)
#define GO_TLS_RET_N(ctx)          ((s64)(ctx)->ax)
#define GO_TLS_RET_ERR_TYPE(ctx)   ((u64)(ctx)->bx)
#define GO_TLS_GOROUTINE_PTR(ctx)  ((u64)(ctx)->r14)
#define GO_TLS_SP(ctx)             ((u64)(ctx)->sp)

#elif defined(__TARGET_ARCH_arm64) || defined(__aarch64__)

/* arm64: struct user_pt_regs is used (defined in api_observer.bpf.c shim) */
#define GO_TLS_PARAM_RECEIVER(ctx) ((u64)((const volatile struct user_pt_regs *)(ctx))->regs[0])
#define GO_TLS_PARAM_BUF_PTR(ctx)  ((u64)((const volatile struct user_pt_regs *)(ctx))->regs[3])
#define GO_TLS_PARAM_BUF_LEN(ctx)  ((u64)((const volatile struct user_pt_regs *)(ctx))->regs[1])
#define GO_TLS_RET_N(ctx)          ((s64)((const volatile struct user_pt_regs *)(ctx))->regs[0])
#define GO_TLS_RET_ERR_TYPE(ctx)   ((u64)((const volatile struct user_pt_regs *)(ctx))->regs[5])
#define GO_TLS_GOROUTINE_PTR(ctx)  ((u64)((const volatile struct user_pt_regs *)(ctx))->regs[28])
#define GO_TLS_SP(ctx)             ((u64)((const volatile struct user_pt_regs *)(ctx))->sp)

#else
#error "Unsupported architecture for Go TLS probes"
#endif

/* ---- FD extraction from tls.Conn (kubeshark approach) ---- */

/*
 * go_crypto_tls_get_fd — Extract socket FD from *tls.Conn receiver.
 *
 * The dereference chain: tls.Conn → .conn (Go interface {type, data})
 * → data points to net.TCPConn → .fd (netFD) → .pfd.Sysfd (int)
 *
 * Kubeshark uses the `go:itab.*<type>,net.Conn` symbol to identify
 * which concrete type implements the net.Conn interface and finds the
 * FD offset via DWARF or a known default (0x10).
 *
 * We use a simplified approach: read the interface data pointer at
 * receiver+0x08 (the .conn field in tls.Conn is at offset 0), then
 * dereference to get netFD at offset 0, then read Sysfd at offset 0x10.
 *
 * This matches Go stdlib layout for net.TCPConn embedding net.conn.
 */
static __always_inline s32
go_tls_get_fd(struct pt_regs *ctx, u64 conn_ptr) {
  /* Read tls.Conn.conn — a Go interface {type_ptr, data_ptr} at offset 0 */
  void *conn_iface_data = NULL;
  /* interface data pointer is the second word (offset +8) */
  bpf_probe_read_user(&conn_iface_data, sizeof(conn_iface_data),
                      (void *)(conn_ptr + 8));
  if (!conn_iface_data)
    return -1;

  /* Read the underlying net.conn/net.TCPConn struct pointer */
  void *netfd_ptr = NULL;
  bpf_probe_read_user(&netfd_ptr, sizeof(netfd_ptr), conn_iface_data);
  if (!netfd_ptr)
    return -1;

  /* Read netFD.pfd.Sysfd at offset 0x10 (standard Go stdlib layout) */
  int fd = -1;
  bpf_probe_read_user(&fd, sizeof(fd), (void *)((u64)netfd_ptr + 0x10));
  return (s32)fd;
}

/* ---- Entry probes (same for both architectures) ---- */

/*
 * Entry handler: saves context into ks_go_{write,read}_context.
 * Keyed by (pid << 32 | goroutine_addr) so multiple goroutines
 * in the same process can be tracked independently.
 *
 * The entry also extracts the FD from tls.Conn at entry time.
 * This is important because at the ret point, the receiver register
 * may have been clobbered.
 */
static __always_inline void
go_tls_entry(struct pt_regs *ctx, void *context_map) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u64 pid = pid_tgid >> 32;

  u64 goroutine = GO_TLS_GOROUTINE_PTR(ctx);
  if (!goroutine)
    return;

  u64 key = pid << 32 | (goroutine & 0xFFFFFFFF);

  struct ks_ssl_info info = ks_new_ssl_info();
  info.buffer = (uintptr_t)GO_TLS_PARAM_BUF_PTR(ctx);
  info.buffer_len = (u32)GO_TLS_PARAM_BUF_LEN(ctx);

  /* Extract FD from *tls.Conn receiver at entry time */
  u64 conn_ptr = GO_TLS_PARAM_RECEIVER(ctx);
  s32 fd = go_tls_get_fd(ctx, conn_ptr);
  if (fd > 2)
    info.fd = (__u32)fd;

  bpf_map_update_elem(context_map, &key, &info, BPF_ANY);
}

/*
 * Return handler (attached at each ret instruction offset):
 * Reads return value, looks up saved context, resolves address
 * info via the ks_go_user_kernel maps, and emits the chunk.
 */
static __always_inline void
go_tls_return(struct pt_regs *ctx, void *context_map,
              void *user_kernel_map, u32 flags) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u64 pid = pid_tgid >> 32;

  u64 goroutine = GO_TLS_GOROUTINE_PTR(ctx);
  if (!goroutine)
    return;

  u64 key = pid << 32 | (goroutine & 0xFFFFFFFF);

  struct ks_ssl_info *info_ptr = bpf_map_lookup_elem(context_map, &key);
  if (info_ptr == NULL)
    return;

  struct ks_ssl_info info;
  long err = bpf_probe_read(&info, sizeof(struct ks_ssl_info), info_ptr);
  if (err != 0)
    return;

  /* Delete entry to avoid stale data on re-entry.
   * Unlike OpenSSL, Go TLS doesn't have a double-read pattern. */
  bpf_map_delete_elem(context_map, &key);

  /* Read return value: n (bytes written/read) from R1 register */
  s64 n = GO_TLS_RET_N(ctx);

  /* For reads, update buffer_len from the return value */
  if (flags & TLS_FLAGS_IS_READ_BIT) {
    if (n <= 0)
      return;
    info.buffer_len = (u32)n;
  } else {
    /* For writes, check that n > 0 (no error) */
    if (n <= 0)
      return;
  }

  /* If FD was captured at entry, look up address info */
  if (info.fd != (__u32)ks_invalid_fd) {
    u64 addr_key = pid << 32 | info.fd;
    struct ks_address_info *addr =
        bpf_map_lookup_elem(user_kernel_map, &addr_key);
    if (addr != NULL) {
      info.address_info.family = addr->family;
      if (addr->family == AF_INET) {
        info.address_info.saddr4 = addr->saddr4;
        info.address_info.daddr4 = addr->daddr4;
      } else if (addr->family == AF_INET6) {
        __builtin_memcpy(info.address_info.saddr6, addr->saddr6, 16);
        __builtin_memcpy(info.address_info.daddr6, addr->daddr6, 16);
      }
      info.address_info.sport = addr->sport;
      info.address_info.dport = addr->dport;
    }
  }

  /* Emit via kubeshark perf path */
  int count = (int)info.buffer_len;
  if (count <= 0)
    return;

  ks_output_ssl_chunk(ctx, &info, count, pid_tgid, flags);
}

/* ---- SEC entries ---- */

/*
 * Entry probes — attached at function entry offset.
 * These are regular uprobes (safe for Go programs).
 */
SEC("uprobe/go_tls_write")
int ka_uprobe_go_tls_write(struct pt_regs *ctx) {
  go_tls_entry(ctx, &ks_go_write_context);
  return 0;
}

SEC("uprobe/go_tls_read")
int ka_uprobe_go_tls_read(struct pt_regs *ctx) {
  go_tls_entry(ctx, &ks_go_read_context);
  return 0;
}

/*
 * Return probes — attached at each `ret` instruction offset.
 * These are regular uprobes placed at ret offsets (NOT uretprobes).
 * Multiple instances are attached per function, one per ret instruction.
 */
SEC("uprobe/go_tls_write_ex")
int ka_uprobe_go_tls_write_ex(struct pt_regs *ctx) {
  go_tls_return(ctx, &ks_go_write_context,
                &ks_go_user_kernel_write_context, 0);
  return 0;
}

SEC("uprobe/go_tls_read_ex")
int ka_uprobe_go_tls_read_ex(struct pt_regs *ctx) {
  go_tls_return(ctx, &ks_go_read_context,
                &ks_go_user_kernel_read_context, TLS_FLAGS_IS_READ_BIT);
  return 0;
}
