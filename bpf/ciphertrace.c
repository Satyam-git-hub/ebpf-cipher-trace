// go:build ignore

#include "vmlinux.h"
#include "bpf_core_read.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct
{
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024); // 256 KB ring buffer
} events SEC(".maps");

struct event_t
{
  u32 pid;
  char comm[16];
  char cipher_name[64];
  char protocol_version[32];
};

// For uretprobes, we need to read the return value directly from pt_regs.
// Using BPF_CORE_READ for CO-RE portability across different kernel versions.
// On x86_64, the return value is in the ax register.

SEC("uretprobe/SSL_CIPHER_get_name")
int BPF_URETPROBE(get_name, const char *ret)
{
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  if (!ret)
    return 0;

  struct event_t event = {};
  event.pid = pid;
  bpf_get_current_comm(&event.comm, sizeof(event.comm));

  // Read the cipher name string from userspace
  bpf_probe_read_user_str(&event.cipher_name, sizeof(event.cipher_name), ret);

  bpf_ringbuf_output(&events, &event, sizeof(event), 0);
  return 0;
}

// Hook SSL_get_version separately to get protocol
SEC("uretprobe/SSL_get_ciphers")
int BPF_UPROBE(ssl_get_ciphers, struct pt_regs *regs)
{

  // We can emit a separate event or try to correlate.
  // For now let's emit separate event to see if it works.
  // It might be too noisy if called frequently.

  // Let's rely on cipher name mostly for PQ check.
  return 0;
}
