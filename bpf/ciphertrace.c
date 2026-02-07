// go:build ignore

#include "vmlinux.h"

// Define types expected by bpf_helpers.h if not provided by vmlinux.h
typedef __u64 u64;
typedef __u32 u32;
typedef __u16 u16;
typedef __u8 u8;
typedef unsigned long long __u64;
typedef unsigned int __u32;

#include "bpf_core_read.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Map to store buffer pointer for recvfrom/read
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10240);
  __type(key, u64);   // pid_tgid
  __type(value, u64); // buffer pointer
} active_read_args SEC(".maps");

struct event_t {
  u32 pid;
  char comm[16];
  u32 event_type; // 1 = ClientHello, 2 = ServerHello
  u16 cipher_id;
  u32 data_len; // Length of the TLS Record/Handshake for PQC heuristic
  char cipher_name[64];
};

static __always_inline void parse_server_hello(char *buf, u32 pid, u32 len) {
  // We expect 'buf' to point to the start of the Handshake Message (Type=0x02)

  // ... (parsing logic) ...

  u8 sess_id_len = 0;
  bpf_probe_read_user(&sess_id_len, sizeof(sess_id_len), buf + 38);

  // Cipher Suite is after Session ID
  // Offset = 38 (random+ver+...) + 1 (len byte) + sess_id_len
  int cipher_offset = 38 + 1 + sess_id_len;

  u16 raw_cipher = 0;
  bpf_probe_read_user(&raw_cipher, sizeof(raw_cipher), buf + cipher_offset);

  // Convert Big Endian to Little Endian
  u16 cipher_id = (raw_cipher >> 8) | ((raw_cipher & 0xFF) << 8);

  struct event_t event = {};
  event.pid = pid;
  event.event_type = 2; // ServerHello
  event.cipher_id = cipher_id;
  event.data_len = len;
  bpf_get_current_comm(&event.comm, sizeof(event.comm));

  bpf_ringbuf_output(&events, &event, sizeof(event), 0);
}

static __always_inline void process_input_packet(struct pt_regs *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;
  u64 *buf_ptr;
  long ret;

  buf_ptr = bpf_map_lookup_elem(&active_read_args, &pid_tgid);
  if (!buf_ptr)
    return;

  // Check return value (bytes read)
  ret = PT_REGS_RC(ctx);
  bpf_map_delete_elem(&active_read_args, &pid_tgid); // Always cleanup

  if (ret <= 0)
    return;

  char *buf = (char *)*buf_ptr;
  u8 byte0 = 0;
  // Read first byte to check record type
  bpf_probe_read_user(&byte0, sizeof(byte0), buf);

  if (ret <= 5)
    return; // Too small for useful TLS analysis

  // Case 1: Full TLS Record (0x16 followed by Handshake)
  if (byte0 == 0x16) {
    // Offset 5 is Handshake Msg Type
    u8 msg_type = 0;
    bpf_probe_read_user(&msg_type, sizeof(msg_type), buf + 5);
    if (msg_type == 0x02) {
      parse_server_hello(buf + 5, pid, (u32)ret);
    }
  }
  // Case 2: Split TLS Body (Starts with 0x02)
  // Check if it looks like Server Hello
  else if (byte0 == 0x02) {
    u8 ver_major = 0;
    bpf_probe_read_user(&ver_major, sizeof(ver_major), buf + 4);
    u8 ver_minor = 0;
    bpf_probe_read_user(&ver_minor, sizeof(ver_minor), buf + 5);

    // Check for 0x03 (SSL 3.0 / TLS 1.0/1.1/1.2/1.3 legacy)
    if (ver_major == 0x03) {
      parse_server_hello(buf, pid, (u32)ret);
    }
  }
}

SEC("kprobe/__x64_sys_sendto")
int kprobe_sendto(struct pt_regs *ctx) {
  // Keeping this for potential future ClientHello analysis
  return 0;
}

SEC("kprobe/__x64_sys_recvfrom")
int kprobe_recvfrom(struct pt_regs *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();

  // Unwrapping arguments: __x64_sys_recvfrom(struct pt_regs *regs)
  // The first argument (DI) holds the pointer to the real registers
  struct pt_regs *regs = (struct pt_regs *)PT_REGS_PARM1(ctx);
  u64 buf = 0;

  // Read 2nd argument (SI) from the inner regs
  bpf_probe_read_kernel(&buf, sizeof(buf), &regs->si);

  bpf_map_update_elem(&active_read_args, &pid_tgid, &buf, BPF_ANY);
  return 0;
}

SEC("kretprobe/__x64_sys_recvfrom")
int kretprobe_recvfrom(struct pt_regs *ctx) {
  process_input_packet(ctx);
  return 0;
}

SEC("kprobe/__x64_sys_read")
int kprobe_read(struct pt_regs *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();

  // Unwrapping arguments: __x64_sys_read(struct pt_regs *regs)
  struct pt_regs *regs = (struct pt_regs *)PT_REGS_PARM1(ctx);
  u64 buf = 0;

  // Read 2nd argument (SI) from the inner regs
  bpf_probe_read_kernel(&buf, sizeof(buf), &regs->si);

  bpf_map_update_elem(&active_read_args, &pid_tgid, &buf, BPF_ANY);
  return 0;
}

SEC("kretprobe/__x64_sys_read")
int kretprobe_read(struct pt_regs *ctx) {
  process_input_packet(ctx);
  return 0;
}
