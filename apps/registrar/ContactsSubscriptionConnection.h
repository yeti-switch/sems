#pragma once

#include "RedisConnectionPool.h"
#include "RedisConnection.h"
#include "RedisScript.h"
#include "Config.h"
#include "unit_tests/RegistrarTest.h"

#include <unordered_map>
#include <chrono>

class ContactsSubscriptionConnection
  : public RedisConnectionPool,
    public RedisScriptLoader,
    public Configurable
{
  private:
    friend RegistrarTest;

    //contains data to generate correct keepalive OPTIONS requests
    struct keepalive_ctx_data {
        std::string aor;
        std::string path;
        int interface_id;
        std::chrono::system_clock::time_point next_send;

        keepalive_ctx_data(
            const std::string &aor,
            const std::string &path,
            int interface_id,
            const std::chrono::system_clock::time_point &next_send)
          : aor(aor),
            path(path),
            interface_id(interface_id),
            next_send(next_send)
        {}

        void update(
            const std::string &_aor,
            const std::string &_path,
            int _interface_id,
            const std::chrono::system_clock::time_point &_next_send)
        {
            aor = _aor;
            path = _path;
            interface_id = _interface_id;
            next_send = _next_send;
        }

        void dump(
            const std::string &key,
            const std::chrono::system_clock::time_point &now) const;
        void dump(
            const std::string &key, AmArg &ret,
            const std::chrono::system_clock::time_point &now) const;

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
      : public std::unordered_map<std::string, keepalive_ctx_data>
    {
        AmMutex mutex;
        void dump();
        void dump(AmArg &ret);
    } keepalive_contexts;

    bool use_functions;
    std::chrono::seconds keepalive_interval;
    std::chrono::seconds max_interval_drift;
    uint32_t max_registrations_per_slot;

    RedisConnection* conn;
    RedisScript load_contacts_script;
    std::unordered_map<std::string, AmSipDialog* > uac_dlgs;
    AmMutex uac_dlgs_mutex;

    void process_loaded_contacts(const AmArg &key_arg);
    void process_expired_key(const AmArg &key_arg);

    void clearKeepAliveContexts();
    void removeKeepAliveContext(const std::string &key);

  protected:
    void on_connect(RedisConnection* c) override;
    int init_connection(cfg_t* cfg, RedisConnection*& c);
    void script_loaded(const RedisScript *script, const char *hash) override;
    void process_reply_event(RedisReplyEvent &event) override;

  public:
    ContactsSubscriptionConnection();

    int configure(cfg_t* cfg) override;
    void load_all_scripts(RedisConnection* conn = nullptr) override;
    void process_sip_reply(const AmSipReplyEvent *reply_ev);
    void process(AmEvent* ev) override;

    void on_keepalive_timer();
    void dumpKeepAliveContexts(AmArg &ret) { keepalive_contexts.dump(ret); }
    void createOrUpdateKeepAliveContext(
        const string &key,
        const string &aor,
        const string &path,
        int interface_id,
        const std::chrono::seconds &keep_alive_interval_offset = std::chrono::seconds{0});
};
