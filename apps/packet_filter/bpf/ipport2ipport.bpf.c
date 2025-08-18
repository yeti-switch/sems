#include <xdp/parsing_helpers.h>
#include <linux/pkt_cls.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <time.h>

#include "compiler.h"
#include "shared_struct.h"
#include "bpf_arena_common.h"


char _license[] SEC("license") = "GPL";

int tc_action_block = TC_ACT_UNSPEC;

__arena void *mem = NULL;


struct {
    __uint(type, BPF_MAP_TYPE_ARENA);
    __uint(map_flags, BPF_F_MMAPABLE);
    __uint(max_entries, 1U << 20); /*  1M pages value per arena while validator is still happy */
} arena_map SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, int);
    __type(value, int);
    __uint(max_entries, 256);
} L3_dev_map SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct counter_v4_key);
    __type(value, struct counter_val);
    __uint(max_entries, 10000);
} ipport2ipport_ipv4_cnt_map SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct counter_v6_key);
    __type(value, struct counter_val);
    __uint(max_entries, 10000);
} ipport2ipport_ipv6_cnt_map SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct config_v4_key);
    __type(value, struct config_IP_value);
    __uint(max_entries, 256);
} config_v4_map SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct config_v6_key);
    __type(value, struct config_IP_value);
    __uint(max_entries, 256);
} config_v6_map SEC(".maps");


/** convenient structure for flow tracking */
struct flow_key {
    int ifindex;  // skb->ifindex
    int protocol; // ETH_P_IP / ETH_P_IPV6
    int ip_proto; // TCP/UDP

    struct port_range *range;

    union {
        struct ipv4_pair pair4;
        struct ipv6_pair pair6;
    };

    union {
        __be32 ports;
        __be16 port16[2];
    };
};


/* IP flags. */
#define IP_MF     0x2000 /* Flag: "More Fragments"       */
#define IP_OFFSET 0x1FFF /* "Fragment Offset" part       */
static inline int ip_is_fragment(struct __sk_buff *skb, __u64 nhoff)
{
    return load_half(skb, nhoff + offsetof(struct iphdr, frag_off)) & (IP_MF | IP_OFFSET);
}


static inline void flow_dump(const char *label, struct flow_key *flow)
{
    if (flow->protocol == ETH_P_IP) {
        bpf_printk("%s %s %pI4h:%u - %pI4h:%u", label, flow->ip_proto == IPPROTO_TCP ? "TCP" : "UDP", &flow->pair4.dst,
                   flow->port16[DST_PORT], &flow->pair4.src, flow->port16[SRC_PORT]);
    } else {
        bpf_printk("%s %s %pI6:%u - %pI6:%u", label, flow->ip_proto == IPPROTO_TCP ? "TCP" : "UDP", &flow->pair6.dst,
                   flow->port16[DST_PORT], &flow->pair6.src, flow->port16[SRC_PORT]);
    }
}

static inline __u64 parse_ip(struct __sk_buff *skb, __u64 nhoff, struct flow_key *flow)
{
    __u64         verlen;
    void         *data     = (void *)(long)skb->data;
    void         *data_end = (void *)(long)skb->data_end;
    struct iphdr *iph      = data + nhoff;

    if (data + nhoff + sizeof(struct iphdr) > data_end)
        return nhoff;

    flow->pair4.src = iph->saddr;
    flow->pair4.dst = iph->daddr;

    if (unlikely(ip_is_fragment(skb, nhoff)))
        flow->ip_proto = 0;
    else
        flow->ip_proto = load_byte(skb, nhoff + offsetof(struct iphdr, protocol));

    verlen = load_byte(skb, nhoff + 0 /*offsetof(struct iphdr, ihl)*/);

    if (likely(verlen == 0x45))
        nhoff += 20;
    else
        nhoff += (verlen & 0xF) << 2;

    return nhoff;
}


#define IPV6_MAX_HEADERS 10 /* Number of extension headers that can be skipped */
#define NEXTHDR_AUTH     51 /* Authentication header */

static inline int ipv6_optlen(const struct ipv6_opt_hdr *opthdr)
{
    return (opthdr->hdrlen + 1) << 3;
}

/* https://datatracker.ietf.org/doc/html/rfc4302#section-2.2 Payload Length */
static inline int ipv6_authlen(const struct ipv6_opt_hdr *opthdr)
{
    return (opthdr->hdrlen + 2) << 2;
}


static inline __u64 parse_ipv6(struct __sk_buff *skb, __u64 nhoff, struct flow_key *flow)
{
    void           *data     = (void *)(long)skb->data;
    void           *data_end = (void *)(long)skb->data_end;
    struct ipv6hdr *ip6h     = data + nhoff;
    __u8            nh;

    if (data + nhoff + sizeof(struct ipv6hdr) > data_end)
        return nhoff;

    flow->pair6.src = ip6h->saddr;
    flow->pair6.dst = ip6h->daddr;

    nh = ip6h->nexthdr;
    nhoff += sizeof(struct ipv6hdr);

/** Trying to parse IPv6 extension headers chain */
#pragma unroll
    for (int i = 0; i < IPV6_MAX_HEADERS; i++) {
        struct ipv6_opt_hdr ipv6_opt_hdr;

        if (nh == IPPROTO_UDP || nh == IPPROTO_TCP) {
            flow->ip_proto = nh;
            return nhoff;
        }

        if (nh == NEXTHDR_AUTH)
            nhoff += ipv6_authlen(&ipv6_opt_hdr);
        else
            nhoff += ipv6_optlen(&ipv6_opt_hdr);

        if (bpf_skb_load_bytes(skb, nhoff, &ipv6_opt_hdr, sizeof(ipv6_opt_hdr)) < 0)
            return nhoff;

        nh = ipv6_opt_hdr.nexthdr;
    }

    return nhoff;
}


static int timer_callback(void *map, void *key, struct bpf_timer *timer)
{
    struct counter_val *val;

    val = bpf_map_lookup_elem(map, key);

    if (val) {

        if (&ipport2ipport_ipv4_cnt_map == map) {
            struct counter_v4_key *key4 = key;
            bpf_printk("~del %pI4h - %pI4h", &key4->pair.dst, &key4->pair.src);
        } else {
            struct counter_v6_key *key6 = key;
            bpf_printk("~del %pI6 - %pI6", &key6->pair.dst, &key6->pair.src);
        }

        bpf_map_delete_elem(map, key);
    }

    return 0;
}

#define _BITOPS_LONG_SHIFT 6
#define BITS_PER_LONG      64

static __always_inline int bpf_test_bit_mem(const void *base, long bit)
{
    unsigned long word;
    long          idx;
    long          offs;

    if (bit < 0 || bit >= 65535)
        return 0;

    idx  = bit >> _BITOPS_LONG_SHIFT;
    offs = idx * sizeof(unsigned long);

    bpf_probe_read_kernel(&word, sizeof(word), base + offs);

    return (word >> (bit & (BITS_PER_LONG - 1))) & 1;
}

static int check_port(struct flow_key *flow)
{
    unsigned long *port_range_off = (unsigned long *)(cast_kern(mem) + flow->range->data_offs);
    long           port_bit_nr    = flow->port16[DST_PORT] - flow->range->low_port;
    int            port_state     = bpf_test_bit_mem(port_range_off, port_bit_nr);

    if (flow->protocol == ETH_P_IP) {
        bpf_printk("check_port %s %pI4h:%u in range %u - %u %d", flow->ip_proto == IPPROTO_TCP ? "TCP" : "UDP",
                   &flow->pair4.dst, flow->port16[DST_PORT], flow->range->low_port, flow->range->high_port, port_state);
    } else {
        bpf_printk("check_port %s %pI6:%u in range %u - %u %d", flow->ip_proto == IPPROTO_TCP ? "TCP" : "UDP",
                   &flow->pair6.dst, flow->port16[DST_PORT], flow->range->low_port, flow->range->high_port, port_state);
    }

    return port_state;
}


static inline __u64 do_work_in_range(struct flow_key *flow, struct __sk_buff *skb)
{
    struct counter_v4_key key4;
    struct counter_v6_key key6;
    void                 *map, *key;
    struct counter_val   *val;

    if (flow->protocol == ETH_P_IP) {
        key4.pair  = flow->pair4;
        key4.ports = flow->ports;
        map        = &ipport2ipport_ipv4_cnt_map;
        key        = &key4;
    } else {
        key6.pair  = flow->pair6;
        key6.ports = flow->ports;
        map        = &ipport2ipport_ipv6_cnt_map;
        key        = &key6;
    }

    int is_port_open = check_port(flow);

    val = bpf_map_lookup_elem(map, key);

    /* The only way to pass our validator: 1) traffic to open port AND 2) no history for pair */
    if (is_port_open && !val)
        return TC_ACT_UNSPEC;

    /** Make/Refresh blocked pairs history */

    if (val) {
        __sync_fetch_and_add(&val->packets, 1);
        __sync_fetch_and_add(&val->bytes, skb->len);
    } else {
        struct counter_val init = { .packets = 1, .bytes = skb->len };

        bpf_map_update_elem(map, key, &init, BPF_ANY);
        val = bpf_map_lookup_elem(map, key);

        if (!val)
            return TC_ACT_UNSPEC;

        bpf_timer_init(&val->timer, map, CLOCK_MONOTONIC);
        bpf_timer_set_callback(&val->timer, timer_callback);
    }

    bpf_timer_start(&val->timer, PAIR_TTL_SEC * 1000000000UL, 0);

    return tc_action_block;
}


/**
    Try to add a port range configuration to the flow
*/
static inline int range_lookup(struct flow_key *flow, struct config_IP_value *ip_cfg)
{
    __u16 dport = flow->port16[DST_PORT];

    unsigned ip_cfg_range_size = min(ip_cfg->range_size, RANGES_PER_IP_MAX);

    for (unsigned i = 0; i < ip_cfg_range_size; ++i) {
        struct port_range *range = &ip_cfg->range[i];

        if (dport >= range->low_port && dport <= range->high_port) {
            flow->range = range;
            return 1;
        }
    }

    return 0;
}


SEC("tc")
int tc_prog(struct __sk_buff *skb)
{
    struct config_v4_key key4;
    struct config_v6_key key6;
    void                *cfg_map, *cfg_key;

    if (mem == NULL) {
        // my_kfunc_reg_arena(&arena_map);
        bpf_printk("not seein shared memory!");
        return TC_ACT_UNSPEC;
    }

    struct flow_key flow = { .ifindex = skb->ifindex, .protocol = htons(skb->protocol) };

    /** check if L2 header should exists for ifindex device */
    int  *is_L3_dev = bpf_map_lookup_elem(&L3_dev_map, &flow.ifindex);
    __u64 nhoff     = is_L3_dev ? 0 : ETH_HLEN;

    switch (flow.protocol) {
    case ETH_P_IP:
        nhoff     = parse_ip(skb, nhoff, &flow);
        key4.addr = flow.pair4.dst;
        cfg_map   = &config_v4_map;
        cfg_key   = &key4;
        break;

    case ETH_P_IPV6:
        nhoff      = parse_ipv6(skb, nhoff, &flow);
        key6.addr6 = flow.pair6.dst;
        cfg_map    = &config_v6_map;
        cfg_key    = &key6;
        break;

    default: return TC_ACT_UNSPEC;
    }

    switch (flow.ip_proto) {
        /*    case IPPROTO_TCP: */
    case IPPROTO_UDP: break;
    default:          return TC_ACT_UNSPEC;
    }

    flow.ports = load_word(skb, nhoff);

    flow_dump("<", &flow); // TODO: remove me

    struct config_IP_value *ip_cfg = bpf_map_lookup_elem(cfg_map, cfg_key);

    if (!ip_cfg)
        return TC_ACT_UNSPEC;

    return range_lookup(&flow, ip_cfg) ? do_work_in_range(&flow, skb) : TC_ACT_UNSPEC;
}
