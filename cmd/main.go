package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/cilium/ebpf"
)

const (
	mapName = "tcp_port_map"
)

func main() {
	// Parse port flag
	port := flag.Uint("port", 4040, "TCP port number to drop packets on")
	flag.Parse()

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

	// Update map with port number
	if err := m.Put(uint32(*port), []byte{}); err != nil {
		fmt.Fprintf(os.Stderr, "Error updating BPF map: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("eBPF program loaded and map created with port %d\n", *port)

	// Wait for program to finish (use Ctrl+C to terminate)
	fmt.Println("Press Ctrl+C to exit...")
	select {}
}
