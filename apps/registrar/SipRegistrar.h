#pragma once
#include <AmApi.h>
#include <AmEventFdQueue.h>
#include <AmSipMsg.h>
#include <RpcTreeHandler.h>

#include "Config.h"
#include "RegistrarRedisConnection.h"
#include "ContactsSubscriptionConnection.h"
#include "ampi/SipRegistrarApi.h"
#include "unit_tests/RegistrarTest.h"

#include <string>
using std::string;

#include <map>
using std::map;

#include <list>
using std::list;

#define MOD_NAME "registrar"

using RegistrationIdType = SipRegistrarEvent::RegistrationIdType;
using AorData = SipRegistrarResolveResponseEvent::aor_data;
using Aors = map<RegistrationIdType, list<AorData>>;

class SipRegistrar
  : public AmThread,
    public AmEventFdQueue,
    public AmEventHandler,
    public RpcTreeHandler<SipRegistrar>,
    public Configurable
{
  private:
    friend RegistrarTest;
    static SipRegistrar* _instance;

    int epoll_fd;
    AmEventFd stop_event;
    AmCondition<bool> stopped;
    AmTimerFd keepalive_timer;

    RegistrarRedisConnection registrar_redis;
    ContactsSubscriptionConnection contacts_subscription;

    rpc_handler rpc_show_aors;
    rpc_handler rpc_show_keepalive_contexts;
    rpc_handler rpc_bind;
    rpc_handler rpc_unbind;

    int expires_min;
    int expires_max;
    int expires_default;
    int keepalive_interval;

  protected:
    friend class SipRegistrarFactory;

    void run() override;
    void on_stop() override;
    void process(AmEvent* ev) override;
    void init_rpc_tree() override;
    int configure(cfg_t* cfg) override;

    int init();
    int onLoad();
    int configure(const string& config);
    int reconfigure(const string& config);

    void postRegisterResponse(const string& session_id, const AmSipRequest* req,
            int code, const string& reason, const string& hdrs = "");
    void postResolveResponse(const string& session_id, const Aors& aors = Aors());
    void process_register_request_event(SipRegistrarRegisterRequestEvent& event);
    void process_resolve_request_event(SipRegistrarResolveRequestEvent& event);
    void process_redis_reply_event(RedisReplyEvent& redis_reply);
    void process_redis_reply_register_event(RedisReplyEvent& redis_reply);
    void process_redis_reply_aor_lookup_event(RedisReplyEvent& redis_reply);
    void process_redis_reply_blocking_req_ctx_event(RedisReplyEvent& redis_reply);

  public:
    SipRegistrar();
    virtual ~SipRegistrar();

    static SipRegistrar* instance();
    static void dispose();

    bool is_loaded();
    void reload();
};
