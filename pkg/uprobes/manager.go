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

func (m *Manager) AttachSSLCipherName(uretprobeProg *ebpf.Program, binaryPath string) error {
	symbol := "SSL_CIPHER_get_name"

	// Open executable
	ex, err := link.OpenExecutable(binaryPath)
	if err != nil {
		return fmt.Errorf("failed to open executable: %w", err)
	}

	// Attach Uretprobe
	lRet, err := ex.Uretprobe(symbol, uretprobeProg, nil)
	if err != nil {
		return fmt.Errorf("failed to attach uretprobe: %w", err)
	}
	m.links = append(m.links, lRet)

	return nil
}

func (m *Manager) Close() {
	for _, l := range m.links {
		l.Close()
	}
}
