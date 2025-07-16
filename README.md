# Drop TCP Packets on Configurable Port with eBPF (XDP)

This project implements an eBPF XDP program to drop incoming TCP packets destined for a configurable TCP port (default 4040).

The port number is configurable at runtime via a BPF array map that can be updated from userspace.

---

## Contents

- `drop_tcp_port_kern.c` - eBPF kernel program in C
- `Makefile` - simple build script for the eBPF program
- `user/` - optional user-space loader (not mandatory; `bpftool` can be used for map updates)

---

## Prerequisites

- Linux kernel ≥ 5.0 with eBPF and XDP support
- Utilities: `clang`, `llvm`, `bpftool`, `ip` (from `iproute2`)
- Root privileges to load XDP programs and update BPF maps
- A network interface to attach the program (e.g., `eth0`, `ens33`, etc.)

---

## Build

Build the eBPF program object:


This compiles `drop_tcp_port_kern.c` into `drop_tcp_port_kern.o`.

---

## Load the eBPF program (XDP)

Attach the program to your chosen network interface (replace `<iface>`):


---

## Verify Program Attachment

Check the XDP program attached to the interface:


You should see details of the attached XDP program.

---

## Update the Drop Port

By default, the program drops TCP packets destined for port `4040`.

To change the port:

1. Find the map ID for the port map:


Locate the map named `port_map` and note its `id`.

2. Update the port number at key `0` with the new port in **network byte order**.

For example, to drop port `8080` (decimal 8080 equals hex `0x1F90`):


> **Note:** The port is 16 bits, so only the first two bytes in `value` represent the port. The last two bytes are padded with zero.

---

## Test the Program

Try to connect to the dropped port (should fail):


Try on other ports (should succeed):


---

## Remove the XDP Program

When finished, detach the program:


---

## Clean Build Artifacts


---

## Notes

- A user-space loader can be written to automate loading and map configuration instead of using `bpftool` commands manually.
- Ensure your kernel supports the necessary eBPF and XDP features.
- On some systems, XDP modes (`generic` or `driver`) may need adjustment using `ip` command flags.

---

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

