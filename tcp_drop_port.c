#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>


struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, int);
    __type(value, unsigned short);
    __uint(max_entries, 1);
} tcp_port_map SEC(".maps");

SEC("xdp")
int tcp_drop_port(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    // IP header can have variable length: use ip->ihl
    struct tcphdr *tcp = (void *)ip + ip->ihl * 4;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    int key = 0;
    unsigned short *port = bpf_map_lookup_elem(&tcp_port_map, &key);
    if (!port)
        return XDP_PASS;

    // tcp->dest is in network byte order
    if (tcp->dest == bpf_htons(*port))
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
