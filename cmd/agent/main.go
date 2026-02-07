package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"vbpf-cipher-trace/pkg/ebpf"
	"vbpf-cipher-trace/pkg/probes"

	"github.com/cilium/ebpf/ringbuf"
)

// Event must match the C struct event_t
type Event struct {
	Pid        uint32
	Comm       [16]byte
	EventType  uint32 // 1=ClientHello, 2=ServerHello
	CipherID   uint16
	DataLen    uint32   // Length of TLS Record/Handshake
	CipherName [64]byte // Kept for compatibility but likely empty
}

// CipherSuiteMap maps IANA cipher suite IDs to names
var CipherSuiteMap = map[uint16]string{
	// ... (no changes to map content)
	0x0005: "TLS_RSA_WITH_RC4_128_SHA",
	0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
	0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
	0xC013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
	0xC014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
	0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
	0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
	0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
	0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
	0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
	0x1301: "TLS_AES_128_GCM_SHA256",
	0x1302: "TLS_AES_256_GCM_SHA384",
	0x1303: "TLS_CHACHA20_POLY1305_SHA256",
}

func getCipherName(id uint16) string {
	if name, ok := CipherSuiteMap[id]; ok {
		return name
	}
	return fmt.Sprintf("UNKNOWN_0x%04X", id)
}

func main() {
	log.Println("Starting eBPF-CipherTrace Agent (Kprobe Mode)...")

	// 1. Load eBPF Objects
	objs, err := ebpf.LoadCipherTraceObjects()
	if err != nil {
		log.Fatalf("Failed to load eBPF objects: %v", err)
	}
	defer objs.Close()

	// 2. Initialize Probe Manager
	pm := probes.NewManager()
	defer pm.Close()

	// 3. Attach Kprobes
	if err := pm.AttachKprobes(objs.KprobeSendto(), objs.KprobeRecvfrom(), objs.KretprobeRecvfrom(), objs.KprobeRead(), objs.KretprobeRead()); err != nil {
		log.Fatalf("Failed to attach kprobes: %v", err)
	}

	// 4. Listen for events
	rd, err := ringbuf.NewReader(objs.Events())
	if err != nil {
		log.Fatalf("Creating ring buffer reader: %s", err)
	}
	defer rd.Close()

	go func() {
		log.Println("Waiting for TLS Handshake events...")
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

			if event.EventType == 2 { // ServerHello
				cipherName := getCipherName(event.CipherID)
				pqStatus := "NOT Quantum Safe"

				// Post-Quantum Logic:
				// 1. Check Cipher Name (unlikely for now as IDs reuse AES)
				if isQuantumSafe(cipherName) {
					pqStatus = "Quantum Safe (Likely - Algorithm)"
				} else if event.DataLen > 1000 {
					// 2. Length Heuristic: Kyber/dilithium exchanges are large (>1KB)
					// Standard Handshakes are usually small (<500B)
					pqStatus = fmt.Sprintf("Quantum Safe (Likely - Large Key Exchange %dB)", event.DataLen)
				}

				log.Printf("TLS Handshake: PID=%d COMM=%s Cipher=0x%04X (%s) [%s]",
					event.Pid, comm, event.CipherID, cipherName, pqStatus)
			} else {
				log.Printf("TLS Event: PID=%d COMM=%s Type=%d", event.Pid, comm, event.EventType)
			}
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
