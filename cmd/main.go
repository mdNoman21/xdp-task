package main

import (
	"flag"
	"fmt"
	"os"

	"encoding/binary"

	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

const (
	mapName = "tcp_port_map"
)

func main() {
	port := flag.Uint("port", 4040, "TCP port number to drop packets on")
	iface := flag.String("iface", "", "Network interface to attach XDP program to (required)")
	flag.Parse()

	if *iface == "" {
		fmt.Fprintln(os.Stderr, "--iface flag is required")
		os.Exit(1)
	}

	coll, err := ebpf.LoadCollection("../tcp_drop_port.o")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load eBPF program: %v\n", err)
		os.Exit(1)
	}
	defer coll.Close()

	m := coll.Maps[mapName]
	if m == nil {
		fmt.Fprintln(os.Stderr, "BPF map not found")
		os.Exit(1)
	}

	key := uint32(0)
	portVal := make([]byte, 2)
	binary.BigEndian.PutUint16(portVal, uint16(*port))
	if err := m.Put(key, portVal); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to update BPF map: %v\n", err)
		os.Exit(1)
	}

	prog := coll.Programs["tcp_drop_port"]
	if prog == nil {
		fmt.Fprintln(os.Stderr, "eBPF program not found")
		os.Exit(1)
	}

	ifaceObj, err := net.InterfaceByName(*iface)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Interface %s not found: %v\n", *iface, err)
		os.Exit(1)
	}

	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: ifaceObj.Index,
		Flags:     0, // native mode
	})
	if err != nil {
		fmt.Println("Native XDP not supported, trying generic mode...")
		xdpLink, err = link.AttachXDP(link.XDPOptions{
			Program:   prog,
			Interface: ifaceObj.Index,
			Flags:     2, // XDP_FLAGS_SKB_MODE
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to attach XDP program: %v\n", err)
			os.Exit(1)
		}
	}
	defer xdpLink.Close()

	fmt.Printf("eBPF program loaded, port %d set, attached to %s\n", *port, *iface)
	fmt.Println("Press Ctrl+C to exit...")
	select {}
}
