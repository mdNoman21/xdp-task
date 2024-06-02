#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <netinet/in.h> 


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
    if (eth + 1 > data_end)
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(struct ethhdr);
    if (ip + 1 > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    struct tcphdr *tcp = (struct tcphdr *)(ip + 1);
    if (tcp + 1 > data_end)
        return XDP_PASS;

    unsigned short *port;
    port = bpf_map_lookup_elem(&tcp_port_map, 0);
    if (!port)
        return XDP_PASS;

    if (tcp->dest == *port)
        return XDP_DROP;

    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
