/* openssl_trace.h — SSL_write / SSL_read uprobes.
 *
 * THIS IS WORK IN PROGRESS - Not tested
 *
 * FD extraction: ssl->rbio->num using version-specific offsets
 * from ssl_symaddrs map (populated by Go at startup).
 * Dedup: conn->is_ssl = 1 causes sock_trace.h kprobes to skip,
 * preventing duplicate (encrypted + plaintext) events.
 */
#pragma once
#include "common/macros.h"
#include "common/maps.h"
#include "common/structs.h"

static __attribute__((always_inline)) u32 get_fd_from_ssl(void *ssl_ptr) {
  u32 zero = 0;
  struct ssl_symaddrs *addrs = bpf_map_lookup_elem(&ssl_symaddrs, &zero);
  if (!addrs || addrs->ssl_rbio_offset < 0 || addrs->bio_num_offset < 0) {
    return 0;
  }

  void *rbio = NULL;
  bpf_probe_read_user(&rbio, sizeof(rbio),
                      (void *)((u64)ssl_ptr + addrs->ssl_rbio_offset));
  if (!rbio) {
    return 0;
  }

  int fd = 0;
  bpf_probe_read_user(&fd, sizeof(fd),
                      (void *)((u64)rbio + addrs->bio_num_offset));
  return (u32)fd;
}

/* emit_ssl_event — shared helper for both SSL_write and SSL_read return */
static __attribute__((always_inline)) int
emit_ssl_event(u64 ssl_ptr, void *buf, u32 len, u8 direction) {
  u32 fd = get_fd_from_ssl((void *)ssl_ptr);
  if (fd == 0) {
    return 0;
  }

  u64 pid_tgid = bpf_get_current_pid_tgid();
  struct conn_id cid = {.tgid = (u32)(pid_tgid >> 32), .fd = fd};
  u64 *sp = bpf_map_lookup_elem(&pid_fd_to_sock, &cid);
  if (!sp || *sp == 0)
    return 0;

  u64 sock_ptr = *sp;

  /* Mark connection as SSL — suppresses kprobe path for this sock */
  struct conn_info *conn = bpf_map_lookup_elem(&connections, &sock_ptr);
  if (conn && !conn->is_ssl) {
    conn->is_ssl = 1;
    bpf_map_update_elem(&connections, &sock_ptr, conn, BPF_EXIST);
  }

  u32 zero = 0;
  struct data_event *e = bpf_map_lookup_elem(&event_scratch, &zero);
  if (!e)
    return 0;

  e->flags = FLAG_IS_SSL;
  u32 to_copy = len < MAX_DATA_SIZE ? len : MAX_DATA_SIZE;
  if (bpf_probe_read_user(e->payload, to_copy & (MAX_DATA_SIZE - 1), buf) < 0)
    return 0;
  e->data_len = to_copy;
  if (len > MAX_DATA_SIZE)
    e->flags |= FLAG_TRUNCATED;

  return emit_data_event(sock_ptr, direction);
}

/* SSL_write(SSL *ssl, const void *buf, int num) — plaintext before encrypt */
static __attribute__((always_inline)) int
handle_ssl_write(struct pt_regs *ctx) {
  void *ssl = (void *)PT_REGS_PARM1(ctx);
  void *buf = (void *)PT_REGS_PARM2(ctx);
  int num = (int)PT_REGS_PARM3(ctx);
  if (!ssl || !buf || num <= 0)
    return 0;
  return emit_ssl_event((u64)ssl, buf, (u32)num, DIR_EGRESS);
}

/* SSL_read entry — save (ssl*, buf*) for uretprobe */
static __attribute__((always_inline)) int
handle_ssl_read_entry(struct pt_regs *ctx) {
  void *ssl = (void *)PT_REGS_PARM1(ctx);
  void *buf = (void *)PT_REGS_PARM2(ctx);
  if (!ssl || !buf) {
    return 0;
  }
  u64 pid_tgid = bpf_get_current_pid_tgid();
  struct ssl_read_args args = {.ssl_ptr = (u64)ssl, .buf = (u64)buf};
  bpf_map_update_elem(&active_ssl_read_args, &pid_tgid, &args, BPF_ANY);
  return 0;
}

/* SSL_read return — kernel has filled buf with decrypted data */
static __attribute__((always_inline)) int
handle_ssl_read_return(struct pt_regs *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  struct ssl_read_args *args =
      bpf_map_lookup_elem(&active_ssl_read_args, &pid_tgid);
  if (!args) {
    return 0;
  }
  u64 ssl_ptr = args->ssl_ptr;
  void *buf = (void *)args->buf;
  bpf_map_delete_elem(&active_ssl_read_args, &pid_tgid);

  int ret = (int)PT_REGS_RC(ctx);
  if (ret <= 0 || !buf) {
    return 0;
  }
  return emit_ssl_event(ssl_ptr, buf, (u32)ret, DIR_INGRESS);
}
