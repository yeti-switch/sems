#pragma once

#include "ampi/OptionsProberAPI.h"
#include "OptionsSingleProbe.h"

#include "AmApi.h"
#include "AmEventFdQueue.h"
#include "AmSipEvent.h"
#include "RpcTreeHandler.h"

class OptionsProber : public AmDynInvokeFactory,
                      public AmConfigFactory,
                      // public AmDynInvoke,
                      public AmThread,
                      public AmEventFdQueue,
                      public AmEventHandler,
                      public RpcTreeHandler<OptionsProber>,
                      public StatsCountersGroupsContainerInterface {
    int               epoll_fd;
    AmTimerFd         timer;
    AmEventFd         stop_event;
    AmCondition<bool> stopped;

    // probers container
    std::map<unsigned int, SipSingleProbe *> probers_by_id;
    std::map<string, SipSingleProbe *>       probers_by_tag;
    AmMutex                                  probers_mutex;

    OptionsProber(const string &name);

    void         onSipReplyEvent(AmSipReplyEvent *ev);
    AmDynInvoke *uac_auth_i;

    void checkTimeouts();
    void onServerShutdown();

    void addProberUnsafe(SipSingleProbe *p);
    void removeProberUnsafe(SipSingleProbe *p);
    void processCtlEvent(OptionsProberCtlEvent &e);

  public:
    OptionsProber() = delete;

    // AmPluginFactory
    int onLoad() override;

    // AmConfigFactory
    int configure(const std::string &config) override;
    int reconfigure(const std::string &config) override;

    // EXPORT_FACTORY
    static OptionsProber *instance();

    // AmDynInvokeFactory
    AmDynInvoke *getInstance() override; /* { return instance(); }*/

    // AmThread
    void run() override;
    void on_stop() override;

    // AmEventHandler
    void process(AmEvent *ev) override;

    // RpcTreeHandler
    void init_rpc_tree() override;
    void ShowProbers(const AmArg &args, AmArg &ret);

    // StatCountersGroupsInterface
    void operator()(const string &name, iterate_groups_callback_type callback) override;
};
