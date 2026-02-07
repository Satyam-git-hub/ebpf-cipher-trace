package probes

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type Manager struct {
	links []link.Link
}

func NewManager() *Manager {
	return &Manager{
		links: make([]link.Link, 0),
	}
}

// AttachKprobes attaches the kprobes for sendto, recvfrom, and read.
func (m *Manager) AttachKprobes(kprobeSendto, kprobeRecvfrom, kretprobeRecvfrom, kprobeRead, kretprobeRead *ebpf.Program) error {
	// Kprobe __x64_sys_sendto
	l1, err := link.Kprobe("__x64_sys_sendto", kprobeSendto, nil)
	if err != nil {
		return fmt.Errorf("attaching kprobe sendto: %w", err)
	}
	m.links = append(m.links, l1)

	// Kprobe __x64_sys_recvfrom
	l2, err := link.Kprobe("__x64_sys_recvfrom", kprobeRecvfrom, nil)
	if err != nil {
		return fmt.Errorf("attaching kprobe recvfrom: %w", err)
	}
	m.links = append(m.links, l2)

	// Kretprobe __x64_sys_recvfrom
	l3, err := link.Kretprobe("__x64_sys_recvfrom", kretprobeRecvfrom, nil)
	if err != nil {
		return fmt.Errorf("attaching kretprobe recvfrom: %w", err)
	}
	m.links = append(m.links, l3)

	// Kprobe __x64_sys_read
	l4, err := link.Kprobe("__x64_sys_read", kprobeRead, nil)
	if err != nil {
		return fmt.Errorf("attaching kprobe read: %w", err)
	}
	m.links = append(m.links, l4)

	// Kretprobe __x64_sys_read
	l5, err := link.Kretprobe("__x64_sys_read", kretprobeRead, nil)
	if err != nil {
		return fmt.Errorf("attaching kretprobe read: %w", err)
	}
	m.links = append(m.links, l5)

	return nil
}

func (m *Manager) Close() {
	for _, l := range m.links {
		l.Close()
	}
}
