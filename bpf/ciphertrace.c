#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(key_size, sizeof(u32));
  __uint(value_size, sizeof(u32));
} events SEC(".maps");

struct event_t {
  u32 pid;
  char comm[16];
  char cipher_name[64];
  char protocol_version[32];
};

// We don't need active connection tracking map if we use uretprobe on
// get_cipher_name directly. But we want to associate it with the connection?
// Actually, apps usually call usage functions *after* handshake.
//
// Simple approach: Hook SSL_get_cipher_name.
// Argument 0 is SSL*. We can use that if we want correlation.
// Return value is 'const char *'.

SEC("uretprobe/SSL_CIPHER_get_name")
int BPF_KRETPROBE(uretprobe_ssl_cipher_get_name, const char *ret) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  if (!ret)
    return 0;

  struct event_t event = {};
  event.pid = pid;
  bpf_get_current_comm(&event.comm, sizeof(event.comm));

  // Read the cipher name string from userspace
  bpf_probe_read_user_str(&event.cipher_name, sizeof(event.cipher_name), ret);

  // Placeholder for version, or hook separate function
  // For now, let's just emit the cipher name event.
  // Usually get_cipher_name is called when the user wants to check.
  // CURL calls it in verbose mode or internally.

  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
  return 0;
}

// Hook SSL_get_version separately to get protocol
SEC("uretprobe/SSL_get_version")
int BPF_KRETPROBE(uretprobe_ssl_get_version, const char *ret) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  if (!ret)
    return 0;

  // We can emit a separate event or try to correlate.
  // For now let's emit separate event to see if it works.
  // It might be too noisy if called frequently.

  // Let's rely on cipher name mostly for PQ check.
  return 0;
}
