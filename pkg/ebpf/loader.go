package ebpf

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall" -no-strip -target amd64 bpf ../../bpf/ciphertrace.c -- -I../../internal/bpf

// CipherTraceObjects wraps the generated bpfObjects for external use.
type CipherTraceObjects struct {
	objs *bpfObjects
}

// KprobeSendto returns the kprobe program for sys_sendto.
func (o *CipherTraceObjects) KprobeSendto() *ebpf.Program {
	return o.objs.KprobeSendto
}

// KprobeRecvfrom returns the kprobe program for sys_recvfrom.
func (o *CipherTraceObjects) KprobeRecvfrom() *ebpf.Program {
	return o.objs.KprobeRecvfrom
}

// KretprobeRecvfrom returns the kretprobe program for sys_recvfrom.
func (o *CipherTraceObjects) KretprobeRecvfrom() *ebpf.Program {
	return o.objs.KretprobeRecvfrom
}

// KprobeRead returns the kprobe program for sys_read.
func (o *CipherTraceObjects) KprobeRead() *ebpf.Program {
	return o.objs.KprobeRead
}

// KretprobeRead returns the kretprobe program for sys_read.
func (o *CipherTraceObjects) KretprobeRead() *ebpf.Program {
	return o.objs.KretprobeRead
}

// Events returns the perf event map.
func (o *CipherTraceObjects) Events() *ebpf.Map {
	return o.objs.Events
}

// Close releases all eBPF resources.
func (o *CipherTraceObjects) Close() error {
	if o.objs != nil {
		return o.objs.Close()
	}
	return nil
}

// LoadCipherTraceObjects loads the generated eBPF objects into the kernel.
func LoadCipherTraceObjects() (*CipherTraceObjects, error) {
	// Allow current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("failed to remove memlock limit: %v", err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := &bpfObjects{}
	if err := loadBpfObjects(objs, nil); err != nil {
		return nil, fmt.Errorf("loading eBPF objects: %v", err)
	}

	return &CipherTraceObjects{objs: objs}, nil
}
