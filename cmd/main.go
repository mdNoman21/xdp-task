package main

import (
	"flag"
	"fmt"
	"os"

	"encoding/binary"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

const (
	mapName = "tcp_port_map"
)

func main() {
	// Parse port and interface flags
	port := flag.Uint("port", 4040, "TCP port number to drop packets on")
	iface := flag.String("iface", "", "Network interface to attach XDP program to (required)")
	flag.Parse()

	if *iface == "" {
		fmt.Fprintln(os.Stderr, "Error: --iface flag is required")
		os.Exit(1)
	}

	// Load eBPF program
	coll, err := ebpf.LoadCollection("../tcp_drop_port.o")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading eBPF program: %v\n", err)
		os.Exit(1)
	}
	defer coll.Close()

	// Get BPF map
	m := coll.Maps[mapName]
	if m == nil {
		fmt.Fprintf(os.Stderr, "Error getting BPF map: %v\n", err)
		os.Exit(1)
	}

	// Update map with port number (network byte order)
	key := uint32(0)
	portVal := make([]byte, 2)
	binary.BigEndian.PutUint16(portVal, uint16(*port))
	if err := m.Put(key, portVal); err != nil {
		fmt.Fprintf(os.Stderr, "Error updating BPF map: %v\n", err)
		os.Exit(1)
	}

	// Attach XDP program to interface
	prog := coll.Programs["tcp_drop_port"]
	if prog == nil {
		fmt.Fprintf(os.Stderr, "Error getting eBPF program: %v\n", err)
		os.Exit(1)
	}
	link, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: *iface,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error attaching XDP program: %v\n", err)
		os.Exit(1)
	}
	defer link.Close()

	fmt.Printf("eBPF program loaded, map updated with port %d, and attached to interface %s\n", *port, *iface)

	// Wait for program to finish (use Ctrl+C to terminate)
	fmt.Println("Press Ctrl+C to exit...")
	select {}
}
