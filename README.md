# XDP TCP Port Dropper

## Quick Start

Follow these steps to compile and run the project:

### 1. Compile the eBPF Program
```sh
clang -O2 -g -target bpf -c tcp_drop_port.c -o tcp_drop_port.o
```

### 2. Build the Go Loader
```sh
cd cmd
go build -o main
```

### 3. Run the Program
Run the loader as root, specifying your network interface and the port to drop (replace `eth0` and `4040` as needed):
```sh
sudo ./main --iface eth0 --port 4040
```
- Use `ip link` to list your available network interfaces if you’re unsure of the name.

### 4. Stop the Program
Press `Ctrl+C` in the terminal to stop and detach the XDP program.

---

This project demonstrates how to use eBPF and XDP to drop incoming TCP packets destined for a specific port at the earliest point in the Linux networking stack.

## How It Works
- An eBPF program (`tcp_drop_port.c`) is loaded and attached to a network interface using XDP.
- The program checks each incoming packet. If it is a TCP packet and its destination port matches the configured port, the packet is dropped.
- The port to drop is set via a BPF map, which is updated by the Go loader (`cmd/main.go`).

## Prerequisites
- Linux system with kernel 5.8+ (for XDP and eBPF support)
- clang/llvm (for compiling eBPF C code)
- Go 1.21+
- [libbpf](https://github.com/libbpf/libbpf) and headers (for eBPF development)
- Root privileges (required for loading eBPF programs and attaching XDP)

## Build Instructions

### 1. Compile the eBPF Program
```
clang -O2 -g -target bpf -c tcp_drop_port.c -o tcp_drop_port.o
```

### 2. Build the Go Loader
```
cd cmd
go build -o main
```

## Usage

1. **Attach the XDP program to a network interface:**
   - Replace `eth0` with your actual network interface name (use `ip link` to list interfaces).
   - Replace `4040` with the port you want to drop (default is 4040).

```
sudo ./main --iface eth0 --port 4040
```

2. **Stop the program:**
   - Press `Ctrl+C` to detach the XDP program and exit.

## Notes
- The program only drops incoming TCP packets to the specified port.
- Make sure the interface is not in use by other XDP programs, or detach them first.
- You can verify dropped packets using `tcpdump` or by attempting to connect to the dropped port.

## Troubleshooting
- **Permission denied:** Run as root (use `sudo`).
- **Failed to attach XDP:** Ensure your kernel and NIC support XDP. Try a different interface.
- **No packets dropped:** Double-check the port and interface, and ensure the eBPF program is loaded.

## License
GPL-2.0 (for eBPF program)
