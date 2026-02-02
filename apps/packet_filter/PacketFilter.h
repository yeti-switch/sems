#pragma once

#include <map>
#include <vector>

#include "RpcTreeHandler.h"
#include "AmEventFdQueue.h"
#include "bpf_object.h"

#define PF_QUEUE "packet_filter"

class PacketFilter : public AmDynInvokeFactory,
                     public AmConfigFactory,
                     public RpcTreeHandler,
                     public StatsCountersGroupsContainerInterface,
                     public AmThread,
                     public AmEventFdQueue,
                     public AmEventHandler,
                     public PacketFilterBpf {


    static PacketFilter *_instance;

    void onServerShutdown();
    ~PacketFilter();

    int               epoll_fd;
    AmEventFd         stop_event;
    AmCondition<bool> stopped;

  public:
    PacketFilter(const string &name);

    // Config factory
    int configure(const std::string &config) override;
    int reconfigure(const std::string &config) override;

    AmDynInvoke         *getInstance() override { return instance(); }
    static PacketFilter *instance();
    void                 init_rpc_tree() override;
    int                  onLoad() override;
    void                 onShutdown() override;

    using iterate_pf_counters_callback_type =
        std::function<void(const sockaddr_storage &src, const sockaddr_storage &dst, const counter_val &val)>;

    void dump_config_map(sa_family_t sa_family, AmArg &ret);
    void dump_counter_map(sa_family_t sa_family, __u32 batch_size, iterate_pf_counters_callback_type callback);

    rpc_handler showConfig;
    rpc_handler showCounters;
    rpc_handler setBlockMode;
    rpc_handler setPacketCountThreshold;

    void operator()(const string &name, iterate_groups_callback_type callback) override;

    void run() override;
    void on_stop() override;

    // AmEventHandler ???
    void process(AmEvent *ev) override;
};


struct PfMetricGroup : public StatCountersGroupsInterface {
    struct pf_info {
        map<string, string> labels;
        unsigned long long  pkt_cnt;
    };
    vector<pf_info> data;

    PfMetricGroup()
        : StatCountersGroupsInterface(Gauge)
    {
    }

    void serialize(StatsCountersGroupsContainerInterface::iterate_groups_callback_type callback)
    {
        setHelp("endpoints blocked by packet_filter");
        callback("packet_filter_endpoint_blocked", *this);
    }

    void add_pf_info(const pf_info &info);

    void iterate_counters(iterate_counters_callback_type callback) override
    {
        for (const auto &data : data)
            callback(data.pkt_cnt, data.labels);
    }
};
