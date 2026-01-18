package uprobes

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

func (m *Manager) AttachSSLHandshake(prog *ebpf.Program, binaryPath string) error {
	// Placeholder for symbol lookup
	symbol := "SSL_do_handshake"

	// Open executable
	ex, err := link.OpenExecutable(binaryPath)
	if err != nil {
		return fmt.Errorf("failed to open executable: %w", err)
	}

	// Attach Uprobe
	l, err := ex.Uprobe(symbol, prog, nil)
	if err != nil {
		return fmt.Errorf("failed to attach uprobe: %w", err)
	}

	m.links = append(m.links, l)
	return nil
}

func (m *Manager) Close() {
	for _, l := range m.links {
		l.Close()
	}
}
