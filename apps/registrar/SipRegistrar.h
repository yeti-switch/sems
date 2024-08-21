#pragma once

#include "SipRegistrarConfig.h"
#include "RegistrarRedisClient.h"
#include "ampi/SipRegistrarApi.h"
#include "unit_tests/RegistrarTest.h"

#include <AmApi.h>
#include <AmEventFdQueue.h>
#include <AmSipMsg.h>
#include <RpcTreeHandler.h>
#include <ampi/RedisApi.h>

#include <string>
#include <map>
#include <list>
#include <unordered_map>
#include <chrono>

using std::string;
using std::map;
using std::list;
using std::unordered_map;
using std::chrono::seconds;
using std::chrono::milliseconds;
using std::chrono::system_clock;

using RegistrationIdType = SipRegistrarEvent::RegistrationIdType;
using AorData = SipRegistrarResolveResponseEvent::aor_data;
using Aors = map<RegistrationIdType, list<AorData>>;

class SipRegistrar
  : public AmThread,
    public AmEventFdQueue,
    public AmEventHandler,
    public RpcTreeHandler<SipRegistrar>,
    public RegistrarRedisClient
{
  private:
    friend RegistrarTest;
    static SipRegistrar* _instance;

    int epoll_fd;
    AmEventFd stop_event;
    AmCondition<bool> stopped;

    int expires_min;
    int expires_max;
    int expires_default;
    int bindings_max;
    unsigned int keepalive_failure_code;
    AmTimerFd keepalive_timer;
    seconds keepalive_interval;
    seconds max_interval_drift;
    /*
     * uac_dlgs
     * key: call_id
     * value: pair.first: ka ctx key
     * value: pair.second: dlg ptr
     */
    unordered_map<string, pair<string, unique_ptr<AmSipDialog>>> uac_dlgs;
    uint32_t max_registrations_per_slot;

    //contains data to generate correct keepalive OPTIONS requests
    struct keepalive_ctx_data {
        string aor;
        string path;
        int interface_id;
        system_clock::time_point next_send;
        system_clock::time_point last_sent;
        unsigned int last_reply_code;
        string last_reply_reason;
        milliseconds last_reply_rtt_ms;

        keepalive_ctx_data(const string &aor, const string &path, int interface_id,
            const system_clock::time_point &next_send);
        void update(const string &_aor, const string &_path, int _interface_id,
            const system_clock::time_point &_next_send);
        void dump(const string &key, const system_clock::time_point &now) const;
        void dump(const string &key, AmArg &ret, const system_clock::time_point &now) const;
    };

    /* has 4 modification sources:
     *  add events:
     *   - loading from redis on node start (lua script)
     *  add/update:
     *   - processing of bindings in redis reply
     *  rm events:
     *   - expire events from redis
     *   - del events from redis
     */
    struct KeepAliveContexts
      : public unordered_map<string, keepalive_ctx_data>
    {
        AmMutex mutex;
        void dump();
        void dump(AmArg &ret);
    } keepalive_contexts;

    rpc_handler rpc_show_aors;
    rpc_handler rpc_show_keepalive_contexts;
    rpc_handler rpc_bind;
    rpc_handler rpc_unbind;

    bool fetch_all(AmObject *user_data, int user_type_id, const string &registration_id);
    bool unbind_all(AmObject *user_data, int user_type_id, const string &registration_id);
    bool bind(AmObject *user_data, int user_type_id,
        const string &registration_id, const string &contact, int expires,
        const string &user_agent, const string &path, unsigned short local_if);
    bool resolve_aors(AmObject *user_data, int user_type_id, std::set<string> aor_ids);
    bool load_contacts(AmObject *user_data, int user_type_id);
    bool subscribe(int user_type_id);
    void rpc_bind_(AmObject *user_data, int user_type_id, const AmArg &arg);
    void rpc_unbind_(AmObject *user_data, int user_type_id, const AmArg &arg);
    void rpc_resolve_aors(AmObject *user_data, int user_type_id, const AmArg &arg);

    void on_keepalive_timer();
    void remove_keep_alive_context(const string &key);
    void clear_keep_alive_contexts();
    void dump_keep_alive_contexts(AmArg &ret) { keepalive_contexts.dump(ret); }
    void create_or_update_keep_alive_context(const string &key, const string &aor, const string &path,
        int interface_id, const seconds &keep_alive_interval_offset = seconds{0});

  protected:
    friend class SipRegistrarFactory;

    void run() override;
    void on_stop() override;
    void process(AmEvent* ev) override;
    void init_rpc_tree() override;
    int configure(cfg_t* cfg) override;
    void connect(const Connection &conn) override;
    void on_connect(const string &conn_id, const RedisConnectionInfo &info) override;

    int init();
    int onLoad();
    void post_register_response(const string& session_id, const AmSipRequest* req,
            int code, const string& reason, const string& hdrs = "");
    void post_resolve_response(const string& session_id, const Aors& aors = Aors());
    void process_register_request_event(SipRegistrarRegisterRequestEvent& event);
    void process_resolve_request_event(SipRegistrarResolveRequestEvent& event);
    void process_redis_conn_state_event(RedisConnectionState& event);
    void process_redis_reply_event(RedisReply& event);
    void process_redis_reply_register_event(RedisReply& event);
    void process_redis_reply_resolve_aors_event(RedisReply& event);
    void process_redis_reply_blocking_req_ctx_event(RedisReply& event);
    void process_redis_reply_contact_subscribe_event(RedisReply& event);
    void process_redis_reply_contact_data_event(RedisReply& event);
    void process_redis_reply_unbind_event(RedisReply& event);
    void process_sip_reply(const AmSipReplyEvent &event);

  public:
    SipRegistrar();
    virtual ~SipRegistrar();

    static SipRegistrar* instance();
    static void dispose();
};
