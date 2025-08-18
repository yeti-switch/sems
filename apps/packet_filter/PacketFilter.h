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

    void dump_config_map(sa_family_t sa_family, AmArg &ret);
    void dump_counter_map(sa_family_t sa_family, __u32 batch_size, AmArg &ret);

    rpc_handler showConfig;
    rpc_handler showCounters;
    rpc_handler setBlockMode;

    void run() override;
    void on_stop() override;

    // AmEventHandler ???
    void process(AmEvent *ev) override;
};
