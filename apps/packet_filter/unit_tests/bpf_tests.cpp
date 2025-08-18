#include <gtest/gtest.h>
#include "packet_filter_tester.h"

#include <AmLcConfig.h>

#include <net/if.h>
#include <bpf/bpf.h>
#include <linux/in.h>
#include <linux/bpf.h>
#include <linux/udp.h>
#include <linux/ipv6.h>
#include <linux/socket.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>

uint16_t get_random_port()
{
    return (uint16_t)((double)rand() / (RAND_MAX + 1.0) * 65536.0);
}

struct in_addr get_random_ipv4(void)
{
    struct in_addr ip;
    ip.s_addr = ((uint32_t)(rand() & 0xFF) << 24) | ((uint32_t)(rand() & 0xFF) << 16) |
                ((uint32_t)(rand() & 0xFF) << 8) | ((uint32_t)(rand() & 0xFF));
    return ip;
}
struct __attribute__((packed)) xdp4_data {
    struct ethhdr eth;
    struct iphdr  iph;
    struct udphdr udph;
};

char *fill_xdp4_data(const string &payload, const string &ip, uint16_t port, uint32_t &len)
{
    sockaddr_storage ss;
    am_inet_pton(ip.c_str(), &ss);
    len                 = sizeof(xdp4_data) + payload.size();
    char      *data     = new char[len];
    xdp4_data *xdp_data = (xdp4_data *)data;
    memset(xdp_data->eth.h_dest, 0xff, ETH_ALEN);
    memset(xdp_data->eth.h_source, 0x11, ETH_ALEN);
    xdp_data->eth.h_proto  = htons(ETH_P_IP);
    xdp_data->iph.version  = 4;
    xdp_data->iph.ihl      = 5;
    xdp_data->iph.ttl      = 64;
    xdp_data->iph.protocol = IPPROTO_UDP;
    xdp_data->iph.saddr    = get_random_ipv4().s_addr;
    xdp_data->iph.daddr    = ((sockaddr_in *)&ss)->sin_addr.s_addr;
    xdp_data->iph.tot_len  = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + payload.size());
    xdp_data->udph.source  = htons(get_random_port());
    xdp_data->udph.dest    = htons(port);
    xdp_data->udph.len     = htons(sizeof(struct udphdr) + payload.size());
    memcpy(data + sizeof(xdp4_data), payload.c_str(), payload.size());
    return data;
}

struct in6_addr get_random_ipv6()
{
    struct in6_addr addr;
    for (int i = 0; i < 16; i++) {
        addr.s6_addr[i] = rand() & 0xFF;
    }
    return addr;
}
struct __attribute__((packed)) xdp6_data {
    struct ethhdr  eth;
    struct ipv6hdr iph;
    struct udphdr  udph;
};

char *fill_xdp6_data(const string &payload, const string &ip, uint16_t port, uint32_t &len)
{
    sockaddr_storage ss;
    am_inet_pton(ip.c_str(), &ss);
    len                 = sizeof(xdp6_data) + payload.size();
    char      *data     = new char[len];
    xdp6_data *xdp_data = (xdp6_data *)data;
    memset(xdp_data->eth.h_dest, 0xff, ETH_ALEN);
    memset(xdp_data->eth.h_source, 0x11, ETH_ALEN);
    xdp_data->eth.h_proto  = htons(ETH_P_IPV6);
    xdp_data->iph.version  = 6;
    xdp_data->iph.priority = 0;

    xdp_data->iph.flow_lbl[0] = xdp_data->iph.flow_lbl[1] = xdp_data->iph.flow_lbl[2] = 0;
    xdp_data->iph.payload_len = htons(sizeof(struct udphdr) + payload.size());
    xdp_data->iph.nexthdr     = IPPROTO_UDP;
    xdp_data->iph.hop_limit   = 64;
    in6_addr saddr            = get_random_ipv6();
    memcpy(&xdp_data->iph.saddr, &saddr, sizeof(in6_addr));
    inet_pton(AF_INET6, ip.c_str(), &xdp_data->iph.daddr);
    xdp_data->udph.source = htons(get_random_port());
    xdp_data->udph.dest   = htons(port);
    xdp_data->udph.len    = htons(sizeof(struct udphdr) + payload.size());
    memcpy(data + sizeof(xdp6_data), payload.c_str(), payload.size());
    return data;
}

bool getNextInterfaceIndex(uint32_t &ifindex)
{
    for (int i = ifindex + 1; i < AmConfig.sys_ifs.size(); i++) {
        if (AmConfig.sys_ifs[i].name.empty())
            continue;
        ifindex = if_nametoindex(AmConfig.sys_ifs[i].name.c_str());
        return true;
    }
    return false;
}

TEST(PacketFilterTest, BpfTest)
{
    if (!pf_test.bpf_enable) {
        GTEST_SKIP_("bpf test disable");
    }
    uint32_t ifindex = -1;
    if (!getNextInterfaceIndex(ifindex)) {
        GTEST_SKIP_("absent interface");
    }

    {
        uint32_t len;
        char    *data = fill_xdp4_data("port out range", "127.0.0.1", 10000, len);

        unsigned int ret_val = 0, duration = 0;
        pf_test.bpf_test_run(data, len, ret_val, duration);
        ASSERT_EQ(ret_val, TC_ACT_UNSPEC);
        delete[] data;
    }
    {
        uint32_t len;
        char    *data = fill_xdp4_data("port in range", "127.0.0.1", 20000, len);

        unsigned int ret_val = 0, duration = 0;
        pf_test.bpf_test_run(data, len, ret_val, duration);
        ASSERT_EQ(ret_val, TC_ACT_SHOT);
        delete[] data;
    }
    {
        uint32_t len;
        char    *data = fill_xdp6_data("port out range", "::1", 10000, len);

        unsigned int ret_val = 0, duration = 0;
        pf_test.bpf_test_run(data, len, ret_val, duration);
        ASSERT_EQ(ret_val, TC_ACT_UNSPEC);
        delete[] data;
    }
    {
        uint32_t len;
        char    *data = fill_xdp6_data("port out range", "::1", 20000, len);

        unsigned int ret_val = 0, duration = 0;
        pf_test.bpf_test_run(data, len, ret_val, duration);
        ASSERT_EQ(ret_val, TC_ACT_SHOT);
        delete[] data;
    }
}
