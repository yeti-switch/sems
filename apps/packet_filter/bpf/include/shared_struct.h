#pragma once

#ifdef __BPF__
#include <xdp/parsing_helpers.h>
#else
#include <linux/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#endif

#define PAIR_TTL_SEC      10
#define RANGES_PER_IP_MAX 16


enum { DST_PORT = 0, SRC_PORT };


/** Counters */
struct ipv4_pair {
    __be32 src;
    __be32 dst;
};

struct ipv6_pair {
    struct in6_addr src;
    struct in6_addr dst;
};

struct counter_v4_key {
    struct ipv4_pair pair;
    union {
        __be32 ports;
        __be16 port16[2];
    };
};

struct counter_v6_key {
    struct ipv6_pair pair;
    union {
        __be32 ports;
        __be16 port16[2];
    };
};

struct counter_val {
    struct bpf_timer timer;
    __u64            packets;
    __u64            bytes;
    // any data...
};
/** Counters */


/** Config */
struct config_v4_key {
    __be32 addr;
};

struct config_v6_key {
    struct in6_addr addr6;
};

struct port_range {
    __u16 low_port;
    __u16 high_port;
    __u32 data_size; // this range size in shared memory (8KB max)
    off_t data_offs; // this range offset in shared memory
};

struct config_IP_value {
    unsigned          range_size;
    struct port_range range[RANGES_PER_IP_MAX];
};
/** Config */
