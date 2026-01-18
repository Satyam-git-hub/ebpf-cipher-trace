package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"
	
	"vbpf-cipher-trace/pkg/ebpf"
	"vbpf-cipher-trace/pkg/uprobes"
//	"vbpf-cipher-trace/pkg/cbom"
//	"vbpf-cipher-trace/pkg/metadata"
)

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
	// In a real agent, we would scan for libraries. Here we hardcode a path or just skip.
	// libSSLPath := "/usr/lib/x86_64-linux-gnu/libssl.so.3"
	// err = upManager.AttachSSLHandshake(objs.UprobeSslDoHandshake, libSSLPath)
	// handle err...

	log.Println("Agent running. Press Ctrl+C to exit.")

	// 4. Listen for events (Reader logic would go here)
	
	// Wait for exit signal
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	<-stopper

	log.Println("Stopping agent...")
}
