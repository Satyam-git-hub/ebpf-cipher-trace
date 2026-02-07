package main

import (
	"crypto/tls"
	"fmt"
	"log"
)

func main() {
	// target := "google.com:443"
	target := "google.com:443"

	const X25519Kyber768Draft00 tls.CurveID = 0x6399

	// Create a custom TLS configuration
	// We can optionally force specific cipher suites to test the tracer
	conf := &tls.Config{
		InsecureSkipVerify: true, // For testing purposes
		MinVersion:         tls.VersionTLS13,
		CurvePreferences:   []tls.CurveID{X25519Kyber768Draft00, tls.X25519, tls.CurveP256},
	}

	conn, err := tls.Dial("tcp", target, conf)
	if err != nil {
		log.Fatalf("TLS connection failed: %v", err)
	}
	defer conn.Close()

	// Get the connection state
	state := conn.ConnectionState()

	fmt.Printf("Connected to %s\n", target)
	fmt.Printf("Version: %x\n", state.Version)
	fmt.Printf("HandshakeComplete: %v\n", state.HandshakeComplete)
	fmt.Printf("CipherSuite: 0x%04X (%s)\n", state.CipherSuite, tls.CipherSuiteName(state.CipherSuite))
}
