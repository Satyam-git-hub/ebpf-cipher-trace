package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"vbpf-cipher-trace/pkg/ebpf"
	"vbpf-cipher-trace/pkg/uprobes"

	"github.com/cilium/ebpf/ringbuf"
)

// Event must match the C struct event_t
type Event struct {
	Pid             uint32
	Comm            [16]byte
	CipherName      [64]byte
	ProtocolVersion [32]byte
}

func main() {
	log.Println("Starting eBPF-CipherTrace Agent...")

	// 1. Load eBPF Objects
	objs, err := ebpf.LoadCipherTraceObjects()
	if err != nil {
		log.Fatalf("Failed to load eBPF objects: %v", err)
	}
	defer objs.Close()

	// 2. Initialize Uprobe Manager
	upManager := uprobes.NewManager()
	defer upManager.Close()

	// 3. Attach Uprobes
	libSSLPath := "/lib/x86_64-linux-gnu/libssl.so.3"
	if err := upManager.AttachSSLCipherName(objs.UretprobeSslCipherGetName(), libSSLPath); err != nil {
		log.Printf("Failed to attach probes: %v", err)
	}

	// 4. Listen for events
	// Open a ring buffer reader from the 'Events' map
	rd, err := ringbuf.NewReader(objs.Events())
	if err != nil {
		log.Fatalf("Creating ring buffer reader: %s", err)
	}
	defer rd.Close()

	go func() {
		log.Println("Waiting for events...")
		for {
			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				log.Printf("Read from ring buffer failed: %s", err)
				continue
			}

			// Unmarshal the raw binary data into the Event struct
			var event Event
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
				log.Printf("parsing ring buffer event: %s", err)
				continue
			}

			comm := string(bytes.TrimRight(event.Comm[:], "\x00"))
			cipherName := string(bytes.TrimRight(event.CipherName[:], "\x00"))

			pqStatus := "NOT Quantum Safe"
			if isQuantumSafe(cipherName) {
				pqStatus = "Quantum Safe (Likely)"
			}

			log.Printf("Cipher Trace: PID=%d COMM=%s Cipher='%s' [%s]",
				event.Pid, comm, cipherName, pqStatus)
		}
	}()

	log.Println("Agent running. Press Ctrl+C to exit.")

	// Wait for exit signal
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	<-stopper

	log.Println("Stopping agent...")
}

func isQuantumSafe(cipher string) bool {
	lower := strings.ToLower(cipher)
	// Check for common PQ identifiers or algorithms
	// This is a naive check based on naming conventions.
	pqKeywords := []string{
		"kyber", "dilithium", "ml-kem", "sphincs", "bike", "hqc",
		"frodo", "ntru", "sike", "mceliece",
	}

	for _, kw := range pqKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}
