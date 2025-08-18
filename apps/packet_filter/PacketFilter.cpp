#include "AmPlugIn.h"
#include "AmEventDispatcher.h"
#include "PortMap.h"
#include "PacketFilter.h"

#include <unistd.h>
#include <sip/ip_util.h>
#include <linux/pkt_cls.h>

#include "ipport2ipport.skel.h"
#include "arena_allocator.skel.h"

#define EPOLL_MAX_EVENTS 2048

EXPORT_PLUGIN_CLASS_FACTORY(PacketFilter);
EXPORT_PLUGIN_CONF_FACTORY(PacketFilter);

PacketFilter *PacketFilter::_instance = 0;
BpfObject    *currentBpf              = 0;

PacketFilter *PacketFilter::instance()
{
    if (_instance == nullptr) {
        _instance = new PacketFilter(MOD_NAME);
    }
    return _instance;
}


PacketFilter::PacketFilter(const string &name)
    : AmDynInvokeFactory(name)
    , AmConfigFactory(MOD_NAME)
    , AmEventFdQueue(this)
    , epoll_fd(-1)
    , stopped(false)
{
    _instance = this;
}


PacketFilter::~PacketFilter()
{
    close(epoll_fd);
}

int PacketFilter::configure(const std::string &config)
{
    if (!currentBpf || currentBpf->bpf_prog_load())
        return -1;

    currentBpf->bpf_get_fds();
    currentBpf->configure_L3_map();

    /** Calculate the shared memory region size */
    size_t   config_size = config_parser();
    unsigned PAGE_SIZE   = getpagesize();
    unsigned pages       = (config_size + PAGE_SIZE - 1) / PAGE_SIZE;

    if (currentBpf->run_prog_allocator(pages) == -1) {
        ERROR("run_ebpf_prog() failed");
        return -1;
    }

    currentBpf->reuse_shared_memory();
    for (auto &[ifindex, tc_hook_created] : tc_ifs)
        if (currentBpf->tc_ingress_attach(ifindex, tc_hook_created))
            return -1;

    return 0;
}


int PacketFilter::reconfigure(const std::string &config)
{
    return configure(config);
}


void PacketFilter::run()
{
    int                ret;
    bool               running;
    struct epoll_event events[EPOLL_MAX_EVENTS];

    setThreadName("packet-filter");

    INFO("PacketFilter starting...");

    running = true;

    do {
        ret = epoll_wait(epoll_fd, events, EPOLL_MAX_EVENTS, -1);

        if (ret == -1 && errno != EINTR) {
            ERROR("epoll_wait: %s", strerror(errno));
        }

        if (ret < 1)
            continue;

        for (int n = 0; n < ret; ++n) {
            struct epoll_event &e = events[n];
            int                 f = e.data.fd;

            if (!(e.events & EPOLLIN)) {
                continue;
            }

            if (f == -queue_fd()) {
                clear_pending();
                processEvents();
            } else if (f == stop_event) {
                stop_event.read();
                running = false;
                break;
            }
        }
    } while (running);

    AmEventDispatcher::instance()->delEventQueue(PF_QUEUE);
    epoll_unlink(epoll_fd);
    close(epoll_fd);

    onServerShutdown();
    stopped.set(true);
    INFO("PacketFilter ending...");
}


void PacketFilter::process(AmEvent *ev) {}


int PacketFilter::onLoad()
{
    init_rpc();

    if ((epoll_fd = epoll_create1(0)) == -1) {
        ERROR("epoll_create call failed");
        return -1;
    }

    epoll_link(epoll_fd);
    stop_event.link(epoll_fd);

    AmEventDispatcher::instance()->addEventQueue(PF_QUEUE, this);

    instance()->start();

    return 0;
}


void PacketFilter::onShutdown()
{
    stop(true);
}


void PacketFilter::onServerShutdown()
{
    if (!currentBpf)
        return;
    for (auto &[ifindex, tc_hook_created] : tc_ifs)
        currentBpf->tc_ingress_cleanup(ifindex, tc_hook_created);

    currentBpf->bpf_prog_unload();
}


void PacketFilter::on_stop()
{
    stop_event.fire();
    stopped.wait_for();
}


void PacketFilter::dump_counter_map(sa_family_t sa_family, __u32 batch_size, AmArg &ret)
{
    sockaddr_storage       src, dst;
    struct sockaddr_in    *src_sin, *dst_sin;
    struct sockaddr_in6   *src_sin6, *dst_sin6;
    struct counter_v4_key *key_v4;
    struct counter_v6_key *key_v6;
    struct counter_val    *values;
    size_t                 key_size, value_size;
    void                  *keys;
    int                    map_fd = -1;


    if (sa_family == AF_INET) {
        map_fd   = ipport2ipport_ipv4_cnt_map;
        key_size = sizeof(struct counter_v4_key);
    } else {
        map_fd   = ipport2ipport_ipv6_cnt_map;
        key_size = sizeof(struct counter_v6_key);
    }
    if (map_fd == -1)
        return;

    src.ss_family = dst.ss_family = sa_family;

    src_sin  = (struct sockaddr_in *)&src;
    dst_sin  = (struct sockaddr_in *)&dst;
    src_sin6 = (struct sockaddr_in6 *)&src;
    dst_sin6 = (struct sockaddr_in6 *)&dst;

    keys   = (void *)alloca(key_size * batch_size);
    key_v4 = (counter_v4_key *)keys;
    key_v6 = (counter_v6_key *)keys;

    value_size = sizeof(struct counter_val);
    values     = (struct counter_val *)alloca(value_size * batch_size);

    bool  first = true;
    bool  next  = true;
    __u32 batch;

    do {
        __u32 count = batch_size;
        int   err;

        err = bpf_map_lookup_batch(map_fd, first ? NULL : &batch, &batch, keys, values, &count, NULL);

        if (err < 0 && errno != ENOENT)
            break;

        if (errno == ENOENT)
            next = false;

        for (unsigned i = 0; i < count; i++) {
            char                label[INET6_ADDRSTRLEN * 2 + 16];
            struct counter_val *val = &values[i];

            ret.push(AmArg());
            AmArg &cnt = ret.back();

            if (sa_family == AF_INET) {
                struct counter_v4_key *key = &key_v4[i];

                src_sin->sin_addr.s_addr = key->pair.src;
                dst_sin->sin_addr.s_addr = key->pair.dst;
                snprintf(label, sizeof(label), "%s:%u - %s:%u", am_inet_ntop(&dst).c_str(), key->port16[DST_PORT],
                         am_inet_ntop(&src).c_str(), key->port16[SRC_PORT]);
            } else {
                struct counter_v6_key *key = &key_v6[i];

                src_sin6->sin6_addr = key->pair.src;
                dst_sin6->sin6_addr = key->pair.dst;
                snprintf(label, sizeof(label), "%s:%u - %s:%u", am_inet_ntop(&dst).c_str(), key->port16[DST_PORT],
                         am_inet_ntop(&src).c_str(), key->port16[SRC_PORT]);
            }

            cnt[label]["bytes"] = (long long)val->bytes;
            cnt[label]["pkts"]  = (long long)val->packets;
        }

        first = false;

    } while (next);
}


void PacketFilter::dump_config_map(sa_family_t sa_family, AmArg &ret)
{
    sockaddr_storage     sa   = { .ss_family = sa_family };
    struct sockaddr_in  *sin  = (struct sockaddr_in *)&sa;
    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&sa;
    struct config_v4_key key_v4;
    struct config_v6_key key_v6;
    void                *key    = nullptr, *next_key;
    int                  map_fd = -1;

    if (sa_family == AF_INET) {
        map_fd   = config_v4_map;
        next_key = &key_v4;
    } else {
        map_fd   = config_v6_map;
        next_key = &key_v6;
    }
    if (map_fd == -1)
        return;

    for (;;) {
        struct config_IP_value ip_cfg_val;

        int err = bpf_map_get_next_key(map_fd, key, next_key);

        if (err) {
            if (errno == ENOENT)
                break;

            ERROR("bpf_map_get_next_key");
            break;
        }

        bpf_map_lookup_elem(map_fd, next_key, &ip_cfg_val);

        if (sa_family == AF_INET)
            sin->sin_addr.s_addr = key_v4.addr;
        else
            sin6->sin6_addr = key_v6.addr6;

        ret.push(AmArg());
        AmArg &ipCfg = ret.back();

        string label = am_inet_ntop(&sa);

        for (unsigned i = 0; i < ip_cfg_val.range_size; ++i) {
            port_range *range = &ip_cfg_val.range[i];
            char        buf[16];

            snprintf(buf, sizeof(buf), "%u-%u", range->low_port, range->high_port);
            ipCfg[label].push(buf);
        }

        key = next_key;
    };
}


void PacketFilter::showConfig(const AmArg &args, AmArg &ret)
{
    dump_config_map(AF_INET, ret);
    dump_config_map(AF_INET6, ret);
}


void PacketFilter::showCounters(const AmArg &args, AmArg &ret)
{
    __u32 batch_size = 1024;

    dump_counter_map(AF_INET, batch_size, ret);
    dump_counter_map(AF_INET6, batch_size, ret);
}


void PacketFilter::setBlockMode(const AmArg &args, AmArg &ret)
{
    if (!bpf_prog_filter)
        return;
    bool block_mode = bpf_prog_filter->data->tc_action_block == TC_ACT_SHOT;

    if (args.size() == 1 && str2bool(args[0].asCStr(), block_mode))
        bpf_prog_filter->data->tc_action_block = block_mode ? TC_ACT_SHOT : TC_ACT_UNSPEC;

    ret["block_mode"] = block_mode;
}


void PacketFilter::init_rpc_tree()
{
    auto &show = reg_leaf(root, "show");
    auto &set  = reg_leaf(root, "set");

    reg_method(show, "config", "", "", &PacketFilter::showConfig, this);
    reg_method(show, "counters", "", "", &PacketFilter::showCounters, this);
    reg_method(set, "block_mode", "", "", &PacketFilter::setBlockMode, this);
}
