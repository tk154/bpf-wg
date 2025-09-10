#ifndef COMMON_KERN_H
#define COMMON_KERN_H

#include <stdbool.h>

#include <linux/types.h>
#include <bpf/bpf_endian.h>
#include <sys/socket.h>

#define MAX_MTU 4096


struct packet_data {
    void *ctx;

    void *data;
    void *data_end;
    void *p;

    __u32 ifindex;
    bool is_xdp;
};


__always_inline static
void ip6cpy(__be32 dest[4], const __be32 src[4])
{
    #pragma unroll
    for (int i = 0; i < 4; i++)
        dest[i] = src[i];
}


__always_inline static
bool bpf_xdp_adjust_packet(struct packet_data *pkt, int head, int tail)
{
    struct xdp_md *xdp = (struct xdp_md *)pkt->ctx;
    long ret;

    ret = bpf_xdp_adjust_head(xdp, head);
    if (ret) {
        bpf_printk("bpf_xdp_adjust_head error: %d", ret);
        return false;
    }

    ret = bpf_xdp_adjust_tail(xdp, tail);
    if (ret) {
        bpf_printk("bpf_xdp_adjust_tail error: %d", ret);
        return false;
    }

    pkt->data = (void *)(long)xdp->data;
    pkt->data_end = (void *)(long)xdp->data_end;

    return true;
}

__always_inline static
bool bpf_skb_adjust_packet(struct packet_data *pkt, __s32 head, __s32 tail, sa_family_t family)
{
    struct __sk_buff *skb = (struct __sk_buff *)pkt->ctx;
    __u64 flags;
    long ret;

    if (head > 0) {
        flags = family == AF_INET ? BPF_F_ADJ_ROOM_ENCAP_L3_IPV4 : BPF_F_ADJ_ROOM_ENCAP_L3_IPV6;
        flags &= BPF_F_ADJ_ROOM_ENCAP_L4_UDP;
    }
    else {
        flags = family == AF_INET ? BPF_F_ADJ_ROOM_DECAP_L3_IPV4 : BPF_F_ADJ_ROOM_DECAP_L3_IPV6;
    }

    ret = bpf_skb_adjust_room(skb, head, BPF_ADJ_ROOM_MAC, flags);
    if (ret) {
        bpf_printk("bpf_skb_adjust_room error: %d", ret);
        return false;
    }

    ret = bpf_skb_change_tail(skb, skb->len + tail, 0);
    if (ret) {
        bpf_printk("bpf_skb_change_tail error: %d", ret);
        return false;
    }

    pkt->data = (void *)(long)skb->data;
    pkt->data_end = (void *)(long)skb->data_end;

    return true;
}

__always_inline static
bool bpf_adjust_packet(struct packet_data *pkt, int head, int tail, sa_family_t family)
{
    return pkt->is_xdp ? bpf_xdp_adjust_packet(pkt, -head, tail) :
        bpf_skb_adjust_packet(pkt, head, tail, family);
}


__always_inline static
void bpf_print_ipv4(const char *prefix, const void *ip_addr)
{
    const __u8 *ip = ip_addr;

    bpf_printk("%s%u.%u.%u.%u", prefix, ip[0], ip[1], ip[2], ip[3]);
}

__always_inline static
void bpf_print_ipv6(const char *prefix, const void *ip_addr)
{
    const __u16 *ip = ip_addr;

    bpf_printk("%s%x:%x:%x:%x:%x:%x:%x:%x", prefix,
        bpf_ntohs(ip[0]), bpf_ntohs(ip[1]), bpf_ntohs(ip[2]), bpf_ntohs(ip[3]), 
        bpf_ntohs(ip[4]), bpf_ntohs(ip[5]), bpf_ntohs(ip[6]), bpf_ntohs(ip[7]));
}


#endif
