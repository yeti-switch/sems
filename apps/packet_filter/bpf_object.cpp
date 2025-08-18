#include "bpf_object.h"
#include "ipport2ipport.skel.h"
#include "arena_allocator.skel.h"
#include "AmLcConfig.h"

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/pkt_cls.h>
#include <linux/if.h>

/** tc filter attach point */
#define TC_HANDLE   1000
#define TC_PRIORITY 1000

//  required caps: cap_dac_override,cap_net_admin,cap_sys_admin=eip
/**
[Service]
CapabilityBoundingSet = CAP_DAC_OVERRIDE CAP_NET_ADMIN CAP_SYS_ADMIN
*/

PacketFilterBpf::PacketFilterBpf()
    : config_v4_map(-1)
    , config_v6_map(-1)
    , L3_dev_map(-1)
    , ipport2ipport_ipv4_cnt_map(-1)
    , ipport2ipport_ipv6_cnt_map(-1)
    , shared_mem{}
    , bpf_prog_allocator{}
    , bpf_prog_filter{}
    , bpf_prog_filter_fd(-1)
    , bpf_prog_filter_id(0)
{
    currentBpf = this;
}

PacketFilterBpf::~PacketFilterBpf()
{
    close(config_v4_map);
    close(config_v6_map);
    close(L3_dev_map);
    close(ipport2ipport_ipv4_cnt_map);
    close(ipport2ipport_ipv6_cnt_map);
}

bool PacketFilterBpf::config_update_ranges(off_t &config_offs, MEDIA_info *proto, PortMap &portmap)
{
    const sockaddr_storage ss         = portmap.getSockAddr();
    unsigned               range_size = BITMAP_SIZE(proto->high_port - proto->low_port + 1);
    int                    map_fd     = -1;
    void                  *key;

    if (ss.ss_family == AF_INET) {
        map_fd = config_v4_map;
        key    = &((sockaddr_in *)&ss)->sin_addr;
    } else {
        map_fd = config_v6_map;
        key    = &((sockaddr_in6 *)&ss)->sin6_addr;
    }
    if (map_fd == -1)
        return false;

    struct config_IP_value ip_cfg_val = {};
    struct port_range      range      = {
                  .low_port  = proto->low_port,
                  .high_port = proto->high_port,
                  .data_size = range_size, // Do we really need this ???
                  .data_offs = config_offs,
    };

    if (bpf_map_lookup_elem(map_fd, key, &ip_cfg_val) == 0) {
        if (ip_cfg_val.range_size >= RANGES_PER_IP_MAX) {
            ERROR("RANGES_PER_IP_MAX (%u) has been reached for %s %s", RANGES_PER_IP_MAX, proto->net_if.c_str(),
                  portmap.getAddress().c_str());
            return false;
        }
    }

    ip_cfg_val.range[ip_cfg_val.range_size++] = range;

    if (bpf_map_update_elem(map_fd, key, &ip_cfg_val, 0) != 0) {
        ERROR("bpf_map_update_elem() failed");
        return false;
    }

    ranges.push_back(range);
    unsigned range_n = ranges.size() - 1;

    INFO("Added range_n #%d %s %s %d-%d", range_n, proto->net_if.c_str(), portmap.getAddress().c_str(), proto->low_port,
         proto->high_port);

    using namespace std::placeholders;
    portmap.registerPortCallbacks(std::bind(&PacketFilterBpf::onPortBind, this, range_n, _1),
                                  std::bind(&PacketFilterBpf::onPortUnbind, this, range_n, _1));
    config_offs += range_size;

    return true;
}


size_t PacketFilterBpf::config_parser()
{
    off_t config_offs = 0;

    for (auto &mif : AmConfig.media_ifs) {
        for (auto &proto : mif.proto_info) {
            if (proto->mtype != MEDIA_info::RTP)
                continue;

            proto->initPortmapHandlers([this, &proto, &config_offs](PortMap &portmap) {
                if (config_update_ranges(config_offs, proto, portmap))
                    tc_ifs[proto->net_if_idx] = false;
            });
        }
    }

    DBG("config_size %lld bytes", config_offs);

    return (size_t)config_offs;
}

int PacketFilterBpf::bpf_prog_load()
{
    bpf_prog_allocator = arena_allocator__open();
    if (!bpf_prog_allocator || arena_allocator__load(bpf_prog_allocator) || arena_allocator__attach(bpf_prog_allocator))
    {
        ERROR("arena_allocator initialization failed");
        return -1;
    }
    /* Set the sleepable flag for the program using the arena alloc page helper */
    bpf_program__set_flags(bpf_prog_allocator->progs.alloc_main_arena, BPF_F_SLEEPABLE);

    bpf_prog_filter = ipport2ipport__open();
    if (!bpf_prog_filter || ipport2ipport__load(bpf_prog_filter) || ipport2ipport__attach(bpf_prog_filter)) {
        ERROR("ipport2ipport initialization failed");
        return -1;
    }

    bpf_prog_filter_fd = bpf_program__fd(bpf_prog_filter->progs.tc_prog);

    struct bpf_prog_info info     = {};
    __u32                info_len = sizeof(info);

    if (bpf_prog_get_info_by_fd(bpf_prog_filter_fd, &info, &info_len) == 0)
        bpf_prog_filter_id = info.id;
    else {
        ERROR("bpf_prog_get_info_by_fd() failed");
        return -1;
    }

    return 0;
}

int PacketFilterBpf::bpf_get_fds()
{
    if (!bpf_prog_filter)
        return -1;

    config_v4_map              = bpf_map__fd(bpf_prog_filter->maps.config_v4_map);
    config_v6_map              = bpf_map__fd(bpf_prog_filter->maps.config_v6_map);
    L3_dev_map                 = bpf_map__fd(bpf_prog_filter->maps.L3_dev_map);
    ipport2ipport_ipv4_cnt_map = bpf_map__fd(bpf_prog_filter->maps.ipport2ipport_ipv4_cnt_map);
    ipport2ipport_ipv6_cnt_map = bpf_map__fd(bpf_prog_filter->maps.ipport2ipport_ipv6_cnt_map);
    return 0;
}

void PacketFilterBpf::bpf_prog_unload()
{
    if (bpf_prog_filter)
        ipport2ipport__destroy(bpf_prog_filter);
    if (bpf_prog_allocator)
        arena_allocator__destroy(bpf_prog_allocator);
}

int PacketFilterBpf::run_prog_allocator(int pages_num)
{
    if (!bpf_prog_allocator)
        return -1;

    /* Look here: https://docs.kernel.org/bpf/bpf_prog_run.html */
    int ret;

    LIBBPF_OPTS(bpf_test_run_opts, tattr, .ctx_in = &pages_num, .ctx_size_in = sizeof(pages_num));

    int bpf_prog_fd = bpf_program__fd(bpf_prog_allocator->progs.alloc_main_arena);
    ret             = bpf_prog_test_run_opts(bpf_prog_fd, &tattr);

    if (ret < 0) {
        perror("bpf_prog_test_run_opts() something went wrong");
        return -1;
    }

    return tattr.retval;
}

void PacketFilterBpf::reuse_shared_memory()
{
    if (!bpf_prog_allocator || !bpf_prog_filter)
        return;
    int arena_map_fd = bpf_map__fd(bpf_prog_allocator->maps.arena_map);
    bpf_map__reuse_fd(bpf_prog_filter->maps.arena_map, arena_map_fd);
    bpf_prog_filter->bss->mem = bpf_prog_allocator->bss->mem;
    shared_mem                = (char *)bpf_prog_allocator->bss->mem;
}

int PacketFilterBpf::tc_ingress_cleanup(int ifindex, bool hook_created)
{
    LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = ifindex, .attach_point = BPF_TC_INGRESS);
    LIBBPF_OPTS(bpf_tc_opts, opts, .handle = TC_HANDLE, .priority = TC_PRIORITY);

    bpf_tc_detach(&hook, &opts);

    if (hook_created)
        bpf_tc_hook_destroy(&hook);

    DBG("ifindex=%d tc_hook_destroy %s", ifindex, hook_created ? "YES" : "NO");

    return 0;
}


int PacketFilterBpf::tc_ingress_attach(int ifindex, bool &hook_created)
{
    bool tc_hook_created = false;

    LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = ifindex, .attach_point = BPF_TC_INGRESS);
    LIBBPF_OPTS(bpf_tc_opts, opts_query, .handle = TC_HANDLE, .priority = TC_PRIORITY);
    LIBBPF_OPTS(bpf_tc_opts, opts_attach, .prog_fd = bpf_prog_filter_fd, .handle = TC_HANDLE, .priority = TC_PRIORITY);

    int ret = bpf_tc_hook_create(&hook);

    if (ret == 0)
        tc_hook_created = true;

    if (bpf_tc_query(&hook, &opts_query) == 0)
        opts_attach.flags = BPF_TC_F_REPLACE;

    DBG("ifindex=%d tc_hook_created %s", ifindex, tc_hook_created ? "YES" : "NO");

    if (bpf_tc_attach(&hook, &opts_attach) == 0) {
        hook_created = tc_hook_created;
        return 0;
    }

    ERROR("bpf_tc_attach() failed for ifindex=%d", ifindex);

    if (tc_hook_created)
        bpf_tc_hook_destroy(&hook);

    return -1;
}

int PacketFilterBpf::configure_L3_map()
{
#define MAX_PAYLOAD 4096

    if (L3_dev_map == -1)
        return -1;

    struct sockaddr_nl src_addr = {}, dest_addr = {};
    struct msghdr      msg = {};
    struct nlmsghdr   *nlh;
    struct iovec       iov;
    int                nl_socket, rc = 0;

    nl_socket = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (nl_socket == -1)
        return -1;

    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid    = getpid();
    src_addr.nl_groups = 0;

    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid    = 0;
    dest_addr.nl_groups = 0;

    bind(nl_socket, (struct sockaddr *)&src_addr, sizeof(src_addr));

    nlh = (struct nlmsghdr *)alloca(NLMSG_SPACE(MAX_PAYLOAD));
    memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
    nlh->nlmsg_len   = NLMSG_SPACE(MAX_PAYLOAD);
    nlh->nlmsg_type  = RTM_GETLINK;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;

    iov.iov_base = (void *)nlh;
    iov.iov_len  = nlh->nlmsg_len;

    msg.msg_name    = (void *)&dest_addr;
    msg.msg_namelen = sizeof(dest_addr);
    msg.msg_iov     = &iov;
    msg.msg_iovlen  = 1;

    sendmsg(nl_socket, &msg, 0);

    while (1) {
        memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
        recvmsg(nl_socket, &msg, 0);

        if (nlh->nlmsg_type == NLMSG_DONE)
            break;

        if (nlh->nlmsg_type == NLMSG_ERROR) {
            rc = -1;
            break;
        }

        struct ifinfomsg *ifi_info = (struct ifinfomsg *)NLMSG_DATA(nlh);

        int no_arp = !!(ifi_info->ifi_flags & IFF_NOARP);

        if (no_arp) {
            INFO("Found L3 dev: %d\n", ifi_info->ifi_index);
            bpf_map_update_elem(L3_dev_map, &ifi_info->ifi_index, &no_arp, 0);
        }
    }

    close(nl_socket);
    return rc;
}

void PacketFilterBpf::range_op(range_op_t op, port_range &range, uint16_t port)
{
    if (!shared_mem || port < range.low_port || port > range.high_port)
        return;

    unsigned long *port_range_off = (unsigned long *)(shared_mem + range.data_offs);
    long           port_bit_nr    = port - range.low_port;

    switch (op) {
    case RANGE_OP_PORT_BIND:   set_bit(port_bit_nr, port_range_off); break;
    case RANGE_OP_PORT_UNBIND: clear_bit(port_bit_nr, port_range_off); break;
    default:                   ;
    }
}


void PacketFilterBpf::onPortBind(unsigned range_n, uint16_t port)
{
    range_op(RANGE_OP_PORT_BIND, ranges[range_n], port);
}


void PacketFilterBpf::onPortUnbind(unsigned range_n, uint16_t port)
{
    range_op(RANGE_OP_PORT_UNBIND, ranges[range_n], port);
}
